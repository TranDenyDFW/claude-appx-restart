# Acceptance

Every item from the v1.0.2 security review, and what covers it. `tools/check_acceptance.py`
verifies that each test named here exists, so a row cannot outlive the test it claims.

Rows marked **manual** need administrator access or a real incident, which no automated
test on this machine can provide; they are listed in the plan's manual gate.

## P1 Authenticate the executable installed for the elevated task

| Review item | Evidence |
|---|---|
| Arbitrary bytes in place of the twin stop the install, nothing changes, the error is logged | tests/test_twin.py::test_arbitrary_bytes_are_refused, tests/test_twin.py::test_a_tampered_twin_exits_with_the_safety_stop_code |
| A tampered twin of the same length is refused by the digest alone | tests/test_twin.py::test_a_same_length_tampered_twin_is_refused_by_the_digest_alone |
| A missing or unauthenticated twin exits 2, never as an internal error | tests/test_twin.py::test_a_missing_twin_exits_with_the_safety_stop_code, tests/test_twin.py::test_a_build_without_a_record_exits_with_the_safety_stop_code, tests/test_twin.py::test_the_install_path_never_reports_an_internal_error |
| A valid executable from another release is refused on the embedded digest | tests/test_twin.py::test_a_twin_from_another_release_is_refused |
| A size mismatch with a matching digest is refused | tests/test_twin.py::test_size_mismatch_with_a_matching_digest_is_refused |
| A build with no embedded record refuses to install | tests/test_twin.py::test_a_build_without_an_embedded_record_refuses |
| The twin cannot be replaced or deleted while the installer holds it | tests/test_twin.py::test_an_open_lock_denies_write_rename_and_delete |
| Another program holding the twin is reported, not worked around | tests/test_twin.py::test_authentication_refuses_when_another_program_holds_the_file |
| The installed twin is checked against the embedded record, not a caller-supplied manifest | tests/test_install_transaction.py::test_a_clean_install_produces_one_verified_version_and_one_task |
| The checksum file beside the build is never consulted | tests/test_twin.py::test_the_checksums_file_beside_the_build_is_never_consulted |
| Only the first candidate name is opened; no fall-through to a second file | tests/test_twin.py::test_no_fall_through_when_the_canonical_twin_fails |
| The digest is embedded by a two-stage build that cannot ship a stale record | tests/test_build.py::test_stages_run_in_order_with_the_record_written_between_them, tests/test_build.py::test_the_stage_guard_refuses_every_wrong_combination |
| An existing install and its task are untouched when the twin fails | tests/test_install_transaction.py::test_a_twin_failure_leaves_an_existing_install_and_its_task_untouched |
| Code signing | manual: no signing identity exists; Authenticode is recorded as NotSigned by tools/verify_release.py |

## P1 Establish and verify the Program Files trust boundary

| Review item | Evidence |
|---|---|
| Program Files comes from the shell, not the environment | tests/test_install_trust.py::test_program_files_comes_from_the_shell_not_the_environment |
| A junction or symbolic link at the target or any child path is rejected | tests/test_install_trust.py::test_a_junction_inside_the_root_is_refused, tests/test_install_trust.py::test_a_junction_at_program_files_is_refused |
| A hard-linked file in the tree is rejected | tests/test_install_trust.py::test_a_hard_linked_file_in_the_root_is_refused |
| A new folder is created with an explicit protected permission list | tests/test_install_trust.py::test_a_fresh_root_is_created_protected_and_verified |
| A pre-existing folder is repaired and re-verified, or refused | tests/test_install_trust.py::test_an_existing_root_with_a_repairable_verdict_is_corrected, tests/test_install_trust.py::test_an_existing_root_with_a_blocking_verdict_is_refused, tests/test_install_trust.py::test_a_repair_that_does_not_hold_is_refused |
| A folder that cannot be protected leaves nothing behind | tests/test_install_trust.py::test_a_failed_permission_apply_leaves_no_folder_behind |
| The permission list is judged exactly, including deny and unsupported entry types | tests/test_security.py::test_a_deny_entry_is_blocking, tests/test_security.py::test_a_conditional_entry_is_blocking_because_it_is_not_interpreted, tests/test_security.py::test_every_single_write_bit_is_caught_for_an_untrusted_principal |
| A standard user cannot overwrite, rename or delete the installed executable | tests/test_security_windows.py::test_a_standard_user_is_denied_write_rename_and_delete, tests/test_security_windows.py::test_with_the_canonical_owner_even_permission_changes_are_denied (elevated only), and the check is proven able to fail by tests/test_security_windows.py::test_the_denial_check_can_fail |
| Status reports the verified canonical task executable and the permission result | tests/test_install_transaction.py::test_status_reports_each_version_and_notices_a_changed_file, tests/test_install_transaction.py::test_status_says_so_when_nothing_is_installed, tests/test_task_xml.py::test_a_task_running_another_executable_is_rejected |

## P1 Close the Job-membership validation race

| Review item | Evidence |
|---|---|
| A process added between snapshots stops the repair, with no termination | tests/test_recovery_race.py::test_a_member_added_during_validation_stops_the_repair, tests/test_recovery_race.py::test_a_member_added_after_validation_stops_the_repair |
| A reused process number stops the repair | tests/test_recovery_race.py::test_a_reused_process_number_stops_the_repair |
| A member that exits with no replacement may be re-validated and then succeed | tests/test_recovery_race.py::test_a_member_leaving_during_validation_is_retried_and_succeeds, tests/test_recovery_race.py::test_a_member_leaving_after_validation_is_retried_and_succeeds |
| A process added after the final check cannot be terminated: membership is frozen | tests/test_recovery_race.py::test_a_member_added_between_the_final_snapshots_stops_the_repair, tests/test_job_freeze_windows.py::test_the_freeze_is_what_stops_a_process_from_joining |
| A Job whose membership cannot be frozen is refused | tests/test_recovery_race.py::test_a_job_that_cannot_be_frozen_is_never_terminated, tests/test_recovery_race.py::test_a_freeze_that_cannot_be_applied_is_never_terminated |
| Start-time checks are preserved so a reused number cannot satisfy validation | tests/test_recovery_race.py::test_a_reused_process_number_stops_the_repair |
| A member that cannot be verified before termination stops the repair | tests/test_recovery_race.py::test_a_member_that_cannot_be_verified_before_termination_stops_the_repair |
| The freeze is always restored and the handle always closed | tests/test_recovery_race.py::test_the_freeze_is_restored_when_a_later_query_fails, tests/test_recovery_race.py::test_the_freeze_is_restored_when_termination_fails |
| The shipped self-check exercises the same driver | tests/test_recovery_race.py::test_the_shipped_self_check_runs_the_race_fixtures, tests/test_build.py::test_a_self_check_that_fails_a_race_guard_stops_the_build |
| The real kernel behaves as assumed | tests/test_job_freeze_windows.py::test_the_limit_structures_match_the_documented_x64_layout, tests/test_job_freeze_windows.py::test_termination_empties_the_job |

## P1 Make published releases immutable and complete

| Review item | Evidence |
|---|---|
| A failure after any upload leaves the release a draft | tests/test_release_workflow.py::test_a_failure_during_upload_leaves_the_release_a_draft, tests/test_release_workflow.py::test_an_upload_that_arrives_corrupted_stops_before_publishing |
| A rerun against an identical published release changes nothing | tests/test_release_workflow.py::test_an_identical_published_release_is_left_alone |
| A changed artifact under the same tag fails and mutates nothing | tests/test_release_workflow.py::test_a_published_release_that_differs_fails_without_touching_it |
| Publishing happens only when the asset set and digests are complete and exact | tests/test_release_workflow.py::test_a_clean_run_publishes_only_after_every_asset_verifies, tests/test_release_workflow.py::test_an_asset_still_uploading_stops_before_publishing |
| The build job stays read-only and the release job runs no repository code | manual: reviewed in .github/workflows/build.yml, permissions and the absence of a checkout |
| The published bytes are bound to the commit that was built | tests/test_release_workflow.py::test_a_tag_that_moved_after_the_build_is_refused |
| Ambiguous release state is refused rather than guessed | tests/test_release_workflow.py::test_two_drafts_for_one_tag_are_refused, tests/test_release_workflow.py::test_a_draft_holding_an_unexpected_file_is_refused |
| Immutability is required, not assumed | tests/test_release_workflow.py::test_a_published_release_that_is_not_immutable_fails, tests/test_release_workflow.py::test_a_publish_that_does_not_become_immutable_is_reported |
| A release lookup that fails is never read as no published release, in the workflow or before tagging | tests/test_release_workflow.py::test_a_release_lookup_that_fails_is_not_read_as_unpublished, tests/test_release_preflight.py::test_a_lookup_that_fails_is_not_read_as_unpublished, tests/test_release_preflight.py::test_an_unpublished_tag_is_ready |
| An independent download matches the published digests | tests/test_verify_release.py::test_a_release_that_matches_reports_no_problems, tests/test_verify_release.py::test_a_tampered_checksums_file_cannot_vouch_for_the_executables, manual gate item 8 |
| The published checksum file is readable by sha256sum on any platform | tests/test_build.py::test_the_checksum_file_is_readable_by_sha256sum_everywhere |

## P2 Make install and upgrade transactional

| Review item | Evidence |
|---|---|
| Failure before and after each staged file leaves the prior task and version runnable | tests/test_install_transaction.py::test_a_failure_while_staging_leaves_the_previous_install_untouched, tests/test_install_transaction.py::test_a_failed_rename_reports_a_retry_and_changes_nothing |
| A registration failure restores the previous task action | tests/test_install_transaction.py::test_a_registration_failure_restores_the_previous_task_definition, tests/test_install_transaction.py::test_a_registration_failure_with_no_previous_task_removes_the_new_one |
| A post-registration verification failure restores the previous task action | tests/test_install_transaction.py::test_a_task_that_verifies_wrong_is_rolled_back |
| A version that fails its post-commit check never becomes the task's target | tests/test_install_transaction.py::test_a_version_that_fails_its_final_check_is_set_aside_and_no_task_is_registered |
| An upgrade while recovery is running reports a retry without a mixed installation | tests/test_install_transaction.py::test_the_running_version_is_left_in_place_with_a_retry, tests/test_remove.py::test_the_folder_this_program_runs_from_is_left_in_place |
| A successful upgrade leaves one verified task action and one immutable version folder | tests/test_install_transaction.py::test_a_clean_install_produces_one_verified_version_and_one_task |
| Upgrading from the currently registered source-based task | tests/test_install_transaction.py::test_an_upgrade_from_a_source_task_registers_the_versioned_executable, tests/test_install_transaction.py::test_a_forced_failure_restores_the_exact_source_task_definition, manual gate item 3 |
| The executable a live task refers to is never overwritten | tests/test_install_transaction.py::test_an_older_installer_refuses_to_replace_a_newer_version, tests/test_install_transaction.py::test_an_upgrade_from_the_flat_layout_removes_the_old_files |
| A task lookup that fails is an error, never an absent task: install stops before it creates or repairs the install folder, and removal and status stop before changing anything | tests/test_install_transaction.py::test_a_task_query_that_fails_stops_before_anything_is_staged, tests/test_install_transaction.py::test_a_task_query_that_fails_on_a_first_install_creates_nothing, tests/test_install_transaction.py::test_a_lookup_that_fails_registers_nothing, tests/test_cli.py::test_removal_stops_before_deleting_anything_when_the_task_cannot_be_queried, tests/test_cli.py::test_status_reports_a_failed_query_as_an_error_not_as_absent, tests/test_task_xml.py::test_a_query_that_fails_raises_instead_of_reporting_absent, tests/test_task_xml.py::test_only_a_lookup_that_found_no_task_reports_it_absent |
| A task that does not exist is still reported absent by the real Task Scheduler | tests/test_task_xml.py::test_a_task_that_does_not_exist_is_reported_absent_not_as_an_error |
| A lookup denied under a restricted token is reported as an error | manual: on a test machine, `--automation-status` run through `runas /trustlevel:0x20000` against an installed task, where Get-ScheduledTask fails with "Cannot connect to CIM server. Access denied" |
| A registered task that cannot be checked afterwards is rolled back like one that checks wrong | tests/test_install_transaction.py::test_a_new_registration_that_cannot_be_checked_restores_the_previous_task, tests/test_install_transaction.py::test_a_new_registration_that_cannot_be_checked_is_removed_when_there_was_none |
| A rollback whose task delete fails says so instead of reporting the task removed, unless the task is confirmed absent, as after a registration that was refused | tests/test_install_transaction.py::test_a_rollback_delete_that_fails_is_reported_not_claimed, tests/test_install_transaction.py::test_a_rollback_that_cannot_tell_whether_the_task_is_gone_is_reported_not_claimed, tests/test_install_transaction.py::test_a_registration_failure_with_no_previous_task_removes_the_new_one |

## P2 Fail closed when the Claude application ID is unknown

| Review item | Evidence |
|---|---|
| A manifest command failure refuses installation | tests/test_package_identity.py::test_manifest_failure_is_unknown_and_keeps_the_error |
| Malformed manifest output refuses installation | tests/test_package_identity.py::test_malformed_manifest_reported_as_an_error_is_unknown |
| An empty application list refuses installation | tests/test_package_identity.py::test_empty_application_list_is_unknown, tests/test_package_identity.py::test_blank_ids_count_as_no_applications |
| Several ambiguous applications refuse installation | tests/test_package_identity.py::test_ambiguous_applications_are_unknown, tests/test_package_identity.py::test_duplicate_expected_ids_are_ambiguous |
| A confirmed expected id may install | tests/test_package_identity.py::test_one_application_is_confirmed, tests/test_package_identity.py::test_several_applications_with_exactly_one_expected_id_resolve |
| A confirmed different id names both observed and expected identities | tests/test_package_identity.py::test_one_different_application_is_confirmed_but_reported |
| The underlying manifest error is preserved in diagnostics | tests/test_package_identity.py::test_manifest_failure_is_unknown_and_keeps_the_error |
| Nothing is terminated while the identity is unknown | tests/test_cli.py::test_manual_run_refuses_before_touching_jobs, tests/test_cli.py::test_event_triggered_run_refuses_and_reports_zero_to_the_scheduler, tests/test_cli.py::test_scan_stays_read_only_when_appinfo_is_stopped |
| A scan still reports a stale Job and exits 10 when the identity is unknown | tests/test_cli.py::test_scan_reports_a_stale_job_even_when_the_identity_is_unknown |

## P2 Preserve logs when elevation does not start

| Review item | Evidence |
|---|---|
| A cancelled prompt exits 1 and logs the reason | tests/test_elevation.py::test_a_cancelled_prompt_leaves_the_reason_on_disk |
| A launch failure and a missing process handle each produce a durable log | tests/test_elevation.py::test_a_failed_launch_leaves_the_reason_on_disk, tests/test_elevation.py::test_a_missing_process_handle_leaves_the_reason_on_disk |
| A wait failure produces a durable log | tests/test_elevation.py::test_a_failed_wait_leaves_the_reason_on_disk, tests/test_elevation.py::test_a_failed_exit_code_read_leaves_the_reason_on_disk |
| A successful elevation leaves one authoritative child result, not overwritten | tests/test_elevation.py::test_a_child_that_wrote_its_log_is_never_overwritten, tests/test_elevation.py::test_a_log_written_after_the_check_is_not_replaced |
| The parent still explains itself when the child wrote nothing | tests/test_elevation.py::test_a_child_that_wrote_no_log_leaves_the_parents_account, tests/test_elevation.py::test_a_stale_log_from_an_earlier_run_is_replaced |

## P2 Remove only files owned by this installation

| Review item | Evidence |
|---|---|
| An unrelated file and an unrecorded same-named file survive removal | tests/test_remove.py::test_a_file_the_installer_never_placed_survives, tests/test_remove.py::test_an_unrecorded_file_with_a_recorded_name_survives |
| Modified installed files are reported and preserved unless forced | tests/test_remove.py::test_a_changed_file_is_kept_and_reported, tests/test_remove.py::test_a_changed_file_is_removed_only_when_forced |
| Path traversal and reparse-point entries are rejected | tests/test_remove.py::test_an_entry_pointing_outside_the_folder_is_refused, tests/test_remove.py::test_a_junction_in_the_tree_stops_the_removal |
| A clean installation uninstalls completely | tests/test_remove.py::test_a_clean_installation_is_removed_completely, tests/test_remove.py::test_the_legacy_flat_layout_is_removed_too |
| Logs are a documented cleanup choice, removed with their version folder | tests/test_install_transaction.py::test_a_log_beside_a_version_goes_with_that_version |

## Non-blocking cleanup

| Review item | Evidence |
|---|---|
| The payload is defined once and imported by the build and the application | tests/test_build.py::test_the_manifest_lists_every_release_asset_with_its_digest, tests/test_imports.py::test_every_module_follows_the_import_rules |
| Install, elevation and task duties live outside the recovery module | tests/test_imports.py::test_the_recovery_module_holds_no_install_or_task_duties |
| No package module imports the command line, and the leaf modules import nothing from the package | tests/test_imports.py::test_every_module_follows_the_import_rules, tests/test_imports.py::test_the_scan_reports_known_bad_sources |
| Destructive Windows operations sit behind interfaces so failures can be injected | tests/test_recovery_race.py::test_a_job_that_cannot_be_frozen_is_never_terminated, tests/test_install_transaction.py::test_a_failed_rename_reports_a_retry_and_changes_nothing |
| A limit left behind by a killed run is reported and put back | tests/test_recovery_race.py::test_a_limit_left_by_a_killed_run_is_reported, tests/test_recovery_race.py::test_a_job_with_no_previous_limit_is_not_reported |
| The security behaviours listed in the mutation guard each have a test that fails when the behaviour is removed | manual: enforced on every run by tools/mutation_guard.py, which the workflow runs, which fails when one of its listed behaviours can be deleted with the tests still green, and which fails rather than passing quietly when a listed behaviour's code has moved. It is a named list, not a proof about every behaviour in the project |
| A control that skips cannot pass for a control that ran | manual: enforced by tools/unit_tests.py --forbid-skips, which the elevated workflow runs |
| The registered task is compared by handle identity, not only by path | tests/test_install_transaction.py::test_a_task_naming_the_right_path_but_a_different_file_is_refused |
| A tag that moves between the draft and the publish stops without publishing | tests/test_release_workflow.py::test_a_tag_that_moves_before_publishing_stops_without_publishing |
| An asset that changes after its own upload check stops without publishing | tests/test_release_workflow.py::test_an_asset_that_changes_after_its_upload_check_stops_without_publishing |
| The coverage map checker refuses a renamed test, a missing file and a malformed row | tests/test_acceptance_checker.py::test_a_row_naming_a_test_that_does_not_exist_fails, tests/test_acceptance_checker.py::test_a_row_naming_a_tool_that_does_not_exist_fails, tests/test_acceptance_checker.py::test_a_row_that_is_not_two_columns_is_reported |
| A task definition survives an export and a restore, which is what a rollback depends on | tests/test_task_roundtrip_windows.py::test_a_registered_task_survives_an_export_and_a_restore, tests/test_task_roundtrip_windows.py::test_an_absent_task_reports_itself_absent (elevated only, runs on CI) |

## Closing the stale activation error dialog

| Review item | Evidence |
|---|---|
| The dialog captured from a real incident matches, and each rule failing alone refuses it | tests/test_dialogs.py::test_the_captured_production_dialog_matches, tests/test_dialogs.py::test_an_owner_outside_the_shell_is_refused, tests/test_dialogs.py::test_a_property_sheet_is_refused, tests/test_dialogs.py::test_another_package_is_refused |
| Nothing is closed unless the launch ends GREEN, and the dialogs are recorded before launch | tests/test_dialogs.py::test_green_closes_the_dialogs_recorded_before_launch, tests/test_dialogs.py::test_visible_without_an_event_check_leaves_them_open, tests/test_dialogs.py::test_red_leaves_them_open |
| An event log that cannot be read is an error, never no events, so a launch reports VISIBLE rather than GREEN, a trace cannot report CLEAR, an event-triggered run does not report NO ACTION, and no error dialog is closed | tests/test_events.py::test_a_denied_log_is_an_error_not_an_empty_answer, tests/test_events.py::test_a_missing_log_is_an_error_even_though_it_is_also_not_found, tests/test_events.py::test_a_disabled_log_is_an_error_although_nothing_matched, tests/test_events.py::test_a_query_the_real_log_throws_on_is_an_error, tests/test_events.py::test_an_error_with_nothing_read_is_an_error, tests/test_events.py::test_a_query_that_matched_nothing_is_no_events, tests/test_events.py::test_the_real_log_is_read_without_error, tests/test_dialogs.py::test_an_event_log_that_cannot_be_read_leaves_the_dialog_open, tests/test_cli.py::test_an_event_triggered_run_reports_the_error_instead_of_no_action, tests/test_cli.py::test_a_trace_reports_the_error_instead_of_clear, tests/test_dialogs.py::test_visible_without_an_event_check_leaves_them_open |
| One event record that cannot be read does not hide the records that were read | tests/test_events.py::test_a_record_that_cannot_be_read_does_not_hide_the_ones_that_were |
| The post-launch window selects events from the launch onward and not before | tests/test_events.py::test_the_time_window_selects_from_the_moment_given, tests/test_events.py::test_the_window_starts_at_the_launch_in_utc_to_the_millisecond |
| A denied event log is reported on a real machine, and the launch window starts at the launch | manual: on a test machine under `runas /trustlevel:0x20000`, `--trace` and both event queries report that the AppModel event log could not be read, where the previous commit reported TRACE CLEAR under the same token; elevated, the post-launch XPath selects a real 208 or 215 event from one second before it and not from one second after |
| A dialog is closed only when Windows logged the sharing violation it reports | tests/test_dialogs.py::test_no_recent_sharing_violation_leaves_the_dialog_open, tests/test_dialogs.py::test_the_recent_failure_is_read_from_the_event_log |
| A dialog raised after launch, or a window that changed, is never closed | tests/test_dialogs.py::test_a_dialog_that_appeared_after_launch_is_never_closed, tests/test_dialogs.py::test_a_handle_reused_before_dismissal_is_not_touched |
| A real task dialog is closed by pressing OK, which WM_CLOSE alone cannot do | tests/test_dialogs_windows.py::test_the_ok_button_is_pressed_and_the_dialog_closes, tests/test_dialogs_windows.py::test_wm_close_alone_does_not_close_a_task_dialog |
| Dialog handling never raises and never changes the outcome | tests/test_dialogs.py::test_an_error_while_closing_never_escapes, tests/test_dialogs.py::test_a_snapshot_never_raises |
| The manifest executable is read for the selected application and never guessed | tests/test_package_identity.py::test_the_executable_follows_the_selected_id_not_the_position, tests/test_package_identity.py::test_nothing_is_guessed |
| The live sihost dialog from the 2026-09-16 incident was closed by the production code | manual: detected by --error-dialogs with every rule passing, then closed by TDM_CLICK_BUTTON on the first step, with sihost.exe still running afterwards |

## Manual release gate

These need administrator rights, repository administration, or a real incident, so they are performed by hand before v1.0.3 is tagged.

| Gate item | Evidence |
|---|---|
| 1. Immutable releases are enabled for the repository | manual: `gh api repos/TranDenyDFW/claude-appx-restart/immutable-releases` reports enabled, then tools/release_preflight.py passes |
| 2. The freeze is available on a real Claude Job | manual: `ClaudeRestart.exe --scan` reports FREEZE CURRENT available |
| 3. An upgrade from the registered source task | manual: install from the built artifact over the existing source task, then `--automation-status` |
| 4. A standard user cannot overwrite, rename or delete the installed executable | manual: attempt each from a non-elevated prompt and confirm every one is denied |
| 5. Tamper tests on the extracted folder | manual: arbitrary bytes, another release's twin, and a replace after open, each a safety stop with the exported task identical before and after |
| 6. A controlled recovery of a real historical failure | manual: `--trace`, then a repair showing REVALIDATED, FREEZE, CLOSED and GREEN |
| 7. A clean Windows 11 installation | manual: install on a fresh virtual machine |
| 8. Published assets match the immutable digests | manual: tools/verify_release.py against a fresh download, recording Authenticode status and a Defender scan per asset |
