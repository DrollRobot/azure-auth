"""Make a noise at the terminal, to call a human back for an interactive sign-in.

The tests marked ``interactive`` in ``tests/live/`` open a browser sign-in and block until
someone completes it. Whoever started the run is usually not watching, so an agent runs this
first. It is not a test; nothing collects it.

Usage::

    uv run python tests/alert_user.py "Sign-in prompt incoming"
    uv run python tests/alert_user.py --repeat 5 --diagnose

Why it writes to the terminal device directly
---------------------------------------------

The obvious approach, printing ``\\a`` to stdout, fails in exactly the situation this script
exists for: an agent runs the command with stdout redirected to a file, so the bell character
lands in the file and nothing rings. This opens the controlling terminal itself (``CONOUT$``
on Windows, ``/dev/tty`` elsewhere) and writes there, which survives redirection.

The terminal bell is also the only method that works over a remote session. It is the *client*
terminal that makes the sound, so it reaches a laptop connected over RDP or SSH even when the
machine running Python has no sound device at all -- as a Windows Server VM typically does not.
Tone generation is tried as well, since a local user may have silenced the bell instead.
"""

from __future__ import annotations

import argparse
import array
import contextlib
import io
import os
import subprocess
import sys
import tempfile
import time
import wave

__version__ = "1.3.0"

BELL = "\a"


def terminal_device() -> str:
    """Return the path of the controlling terminal for this platform.

    Returns:
        ``CONOUT$`` on Windows, ``/dev/tty`` elsewhere.
    """
    return "CONOUT$" if os.name == "nt" else "/dev/tty"


def ring_terminal(times: int) -> bool:
    """Ring the terminal bell, bypassing any redirection of stdout.

    Args:
        times: How many bells to send.

    Returns:
        ``True`` if the terminal accepted the writes.
    """
    try:
        with open(terminal_device(), "w", encoding="utf-8", errors="replace") as terminal:
            for index in range(times):
                terminal.write(BELL)
                terminal.flush()
                if index < times - 1:
                    time.sleep(0.25)
    except OSError:
        return False
    return True


def beep_levels(beeps: int) -> list[float]:
    """Return the volume of each beep in a burst, as a fraction of full volume.

    The burst rises evenly from half volume to full, so three beeps play at 50%, 75% and
    100%. A single beep plays at full volume.

    Args:
        beeps: How many beeps in the burst.

    Returns:
        One level per beep, each between 0.5 and 1.0.
    """
    quietest = 0.5
    if beeps < 2:
        return [1.0] * beeps
    return [quietest + (1.0 - quietest) * index / (beeps - 1) for index in range(beeps)]


def build_alarm(beeps: int = 3) -> bytes:
    """Build a short alarm as an in-memory WAV.

    Generated rather than taken from the system's sound files, so it is the same on every
    platform and does not resemble any noise the operating system makes on its own.

    The waveform is a square wave, not a sine: its odd harmonics spread the energy across the
    spectrum instead of putting it all at one frequency, which is what lets a short beep stay
    audible over music. 1 kHz sits where hearing is most sensitive, and three abrupt repeats
    read as an alarm rather than a notification. Each beep is louder than the one before, as
    set by :func:`beep_levels`.

    Args:
        beeps: How many beeps in the burst.

    Returns:
        A complete RIFF/WAVE file.
    """
    rate = 44100
    hertz = 1000
    beep_seconds = 0.09
    gap_seconds = 0.06
    peak = 16000  # Loud, but short of the clipping point of a 16-bit sample.
    ramp = 200  # Samples of fade at each edge, enough to avoid a click.

    samples = array.array("h")
    period = rate / hertz
    for index, level in enumerate(beep_levels(beeps)):
        amplitude = int(peak * level)
        count = int(rate * beep_seconds)
        for position in range(count):
            value = amplitude if (position % period) < (period / 2) else -amplitude
            if position < ramp:
                value = int(value * position / ramp)
            elif position > count - ramp:
                value = int(value * (count - position) / ramp)
            samples.append(value)
        if index < beeps - 1:
            samples.extend([0] * int(rate * gap_seconds))

    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(samples.tobytes())
    return buffer.getvalue()


def play_sound() -> bool:
    """Play the alert through the platform's ordinary audio output.

    Returns:
        ``True`` if a sound was handed to the audio stack. Whether a human heard it cannot be
        known from here.
    """
    data = build_alarm()
    if sys.platform == "win32":
        return _play_windows(data)
    return _play_posix(data)


def _play_windows(data: bytes) -> bool:
    """Play WAV data through the Windows audio stack.

    Deliberately not ``winsound.Beep``: that drives the legacy PC-speaker timer, which raises
    ``RuntimeError`` on a machine with no sound hardware -- as a Windows Server VM has none.
    ``PlaySound`` goes through the ordinary audio stack instead, so it reaches the endpoint
    that Remote Desktop audio redirection provides and comes out of the listener's own
    speakers. Measured on such a VM on 2026-09-20: ``Beep`` silent, ``PlaySound`` audible.

    Args:
        data: A complete WAV file.

    Returns:
        ``True`` if it played.
    """
    try:
        import winsound
    except ImportError:
        return False
    try:
        winsound.PlaySound(data, winsound.SND_MEMORY)
    except RuntimeError:
        try:
            winsound.MessageBeep(winsound.MB_ICONHAND)
        except RuntimeError:
            return False
    return True


def _play_posix(data: bytes) -> bool:
    """Play WAV data with whatever command line player is installed.

    Args:
        data: A complete WAV file.

    Returns:
        ``True`` if a player accepted it.
    """
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        players = (
            [["afplay", path]]
            if sys.platform == "darwin"
            else [["paplay", path], ["aplay", "-q", path]]
        )
        return any(_run(command) for command in players)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(path)


def _run(command: list[str]) -> bool:
    """Run a sound player, reporting whether it worked.

    Args:
        command: The player and its argument.

    Returns:
        ``True`` on a zero exit status.
    """
    try:
        completed = subprocess.run(  # noqa: S603 (fixed argv list, no shell)
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except OSError, subprocess.SubprocessError:
        return False
    return completed.returncode == 0


def parse_args() -> argparse.Namespace:
    """Read the command line.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "message",
        nargs="?",
        default="Interactive sign-in needed at this desktop.",
        help="Text to show alongside the sound.",
    )
    parser.add_argument("--repeat", type=int, default=3, help="How many bells to send.")
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Report which methods worked, for when nothing is audible.",
    )
    return parser.parse_args()


def main_for_tests() -> None:
    """Sound the alarm from inside a test, without touching the command line or exit codes.

    A test knows the moment a browser window is about to open, which an agent running this
    script beforehand can only guess at.
    """
    play_sound()
    ring_terminal(1)


def main() -> int:
    """Alert the user.

    Returns:
        ``0`` if at least one method worked, ``1`` if none did.
    """
    args = parse_args()
    print(f"\n  >>> {args.message}\n", flush=True)

    played = False
    for index in range(max(1, args.repeat)):
        played = play_sound() or played
        if index < args.repeat - 1:
            time.sleep(0.2)
    rang = ring_terminal(max(1, args.repeat))

    if args.diagnose:
        print(f"  audio on {sys.platform}: {'played' if played else 'UNAVAILABLE'}")
        print(f"  terminal bell via {terminal_device()}: {'sent' if rang else 'UNAVAILABLE'}")
        if not played and rang:
            print("  Audio failed; only the terminal bell went out, which may be muted.")
        if not played and not rang:
            print("  Nothing worked. Watch for the browser window instead.")
    return 0 if (played or rang) else 1


if __name__ == "__main__":
    raise SystemExit(main())
