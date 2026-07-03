# AgentDojo Replay Sample Gap Report

Trace completeness and benchmark sample sufficiency are reported separately.

- Trace missing count: 0
- Generated unsafe cases: 69
- Generated safe cases: 131
- Phase 1 unsafe target: 50
- Phase 1 safe target: 50
- Phase 1 unsafe shortfall: 0
- Phase 1 safe shortfall: 0
- Skipped successful attacks with missing sink/taxonomy gap: 65
- Estimated minimum additional DeepSeek calls for Phase 1: 0

Cases by suite:
- banking: 67
- slack: 48
- travel: 21
- workspace: 64

Cases by violation type:
- benign_file_or_workspace_side_effect: 43
- benign_user_requested_booking: 18
- benign_user_requested_payment: 49
- benign_user_requested_slack_message: 21
- booking_target_from_untrusted_source: 3
- calendar_side_effect: 6
- destructive_file_operation: 5
- financial_commit_from_untrusted_source: 18
- membership_expansion_from_untrusted_source: 14
- message_channel_from_untrusted_source: 1
- message_recipient_from_untrusted_source: 1
- private_data_exfiltration: 10
- private_data_exfiltration_to_external_sink: 11

Insufficient or missing coverage should be closed only by collecting additional same-model AgentDojo full traces. DeepSeek-chat logs may be used as reference only, not mixed into DeepSeekV4-Flash primary results.
