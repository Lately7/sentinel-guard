from pathlib import Path

import pytest

from sentinel.service import canary


def test_plan_create_revalidate_content_identity_and_missing(tmp_path: Path):
    plan = canary.placement_plan([tmp_path], per_root=2)
    assert len(plan) == 2
    record = canary.create(plan[0])
    assert canary.revalidate(record).status == "INTACT"
    record.path.write_bytes(b"changed")
    assert canary.revalidate(record).status == "CONTENT_CHANGED"
    record.path.unlink()
    record.path.write_bytes(b"replacement")
    assert canary.revalidate(record).status in ("REPLACED", "CONTENT_CHANGED")
    record.path.unlink()
    assert canary.revalidate(record).status == "MISSING"


def test_canary_rejects_escape_existing_file_and_cap(tmp_path: Path):
    with pytest.raises(ValueError):
        canary.create(canary.Placement(tmp_path, Path("../escape.txt"), b"x"))
    placement = canary.placement_plan([tmp_path], per_root=1)[0]
    canary.create(placement)
    with pytest.raises(FileExistsError):
        canary.create(placement)
    with pytest.raises(ValueError):
        canary.placement_plan([tmp_path] * 65, per_root=4)
