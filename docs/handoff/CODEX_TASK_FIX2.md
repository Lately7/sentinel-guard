# Codex fix round FIX2: the walk and the shadow checkpoint (EDGE3)

Worktree: the EDGE3 worktree; the tests are `tests/codex/test_observe_edges.py`.

## Allowed paths

`agent/sentinel/service/reconcile.py`, `agent/sentinel/service/shadow.py`, `tests/codex/test_observe_edges.py`.

## Findings

* `test_saved_descendant_cannot_escape_fixed_drive` (hardening, low): a resume cursor is only validated at its
  root frame, so a forged child frame can walk outside the drive. Check that every saved frame is a descendant of
  the one before it (handle the `\\?\` prefix); otherwise treat the cursor as lost, with its gap.
* `test_junction_loop_and_listing_to_descent_swap_are_not_followed` (product bug, low): a directory replaced by a
  junction between listing and descent is followed. Before descending, check the opened directory itself is not a
  reparse point (open without following reparse points, or compare identity), and count `reparse_skipped`.
* `test_damaged_shadow_checkpoint_is_observation_gap` (product bug, low): a corrupt or truncated checkpoint reads
  as fresh coverage with zero gaps. A missing file is a fresh start; a damaged one is a gap
  (`checkpoint_invalid`).
* `test_long_and_extended_paths_are_walked` is a **test bug**: find why it fails (read the walker's handling of
  the drive root it is given) and make the test exercise long paths the way the product receives drive roots.
