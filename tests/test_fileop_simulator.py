from pathlib import Path

import pytest

from tools import fileop_simulator as sim


def test_harness_reversible_modes_and_marker(tmp_path: Path):
    harness = sim.create_harness(tmp_path)
    files = sim.seed(harness)
    before = {p: p.read_bytes() for p in files}
    events = sim.run(harness, mode="partial", order="reverse", skip_canaries=True, workers=2)
    assert events and all(e.at >= 0 for e in events)
    sim.restore(harness)
    assert all(p.read_bytes() == before[p] for p in files)
    (harness.directory / sim.MARKER).unlink()
    with pytest.raises(ValueError):
        sim.run(harness)


@pytest.mark.parametrize("mode", ["overwrite", "rename", "partial"])
def test_each_transform_mode_restores_exact_corpus(tmp_path: Path, mode: str):
    harness = sim.create_harness(tmp_path)
    files = sim.seed(harness)
    before = [path.read_bytes() for path in files]
    assert sim.run(harness, mode=mode)
    assert any(path.read_bytes() != data for path, data in zip(files, before))
    sim.restore(harness)
    assert [path.read_bytes() for path in files] == before


def test_refuses_unmarked_root_profile_network_and_reparse(tmp_path: Path):
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(tmp_path, "a" * 48))
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(tmp_path / "missing", "a" * 48))
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(Path(tmp_path.anchor), "a" * 48))
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(Path.home(), "a" * 48))
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(Path("//server/share"), "a" * 48))
    harness = sim.create_harness(tmp_path)
    with pytest.raises(ValueError):
        sim.validate(sim.Harness(harness.directory, "b" * 48))
    target = harness.directory / "outside"
    try:
        target.symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError):
        sim.validate(harness)
