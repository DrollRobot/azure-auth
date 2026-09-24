"""Unit tests for the alarm the live tests sound before an interactive sign-in."""

from __future__ import annotations

import array
import io
import wave

import pytest

from tests import alert_user

pytestmark = [pytest.mark.unit]


def beep_peaks(data: bytes) -> list[int]:
    """Return the loudest sample of each beep in a WAV, splitting the beeps on silent gaps.

    Args:
        data: A complete WAV file built by ``build_alarm``.

    Returns:
        One peak absolute sample value per beep, in playing order.
    """
    with wave.open(io.BytesIO(data), "rb") as handle:
        samples = array.array("h", handle.readframes(handle.getnframes()))
    peaks: list[int] = []
    silent_run = 0
    in_beep = False
    for sample in samples:
        if sample == 0:
            silent_run += 1
            # The 200-sample edge ramp touches zero only once; the 60 ms gap is thousands long.
            if in_beep and silent_run > 1000:
                in_beep = False
            continue
        silent_run = 0
        if not in_beep:
            peaks.append(0)
            in_beep = True
        peaks[-1] = max(peaks[-1], abs(sample))
    return peaks


def test_three_beeps_rise_from_half_to_full_volume() -> None:
    assert alert_user.beep_levels(3) == [0.5, 0.75, 1.0]


def test_a_single_beep_plays_at_full_volume() -> None:
    assert alert_user.beep_levels(1) == [1.0]


def test_levels_rise_evenly_for_longer_bursts() -> None:
    assert alert_user.beep_levels(5) == [0.5, 0.625, 0.75, 0.875, 1.0]


def test_the_rendered_alarm_gets_louder_with_each_beep() -> None:
    assert beep_peaks(alert_user.build_alarm()) == [8000, 12000, 16000]
