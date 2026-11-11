Output demo/agentfence-demo.gif
Output demo/agentfence-demo.webm

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 550
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set PlaybackSpeed 1

# Title
Type "# agentfence: SQL-aware policy engine for AI agents"
Enter
Sleep 1s
Enter

# Step 1: Safe query — ALLOWED
Type "# 1. Agent asks for order stats (safe query)"
Enter
Sleep 500ms
Type "agentfence check -p demo/policy.yaml -a analytics-bot -A query_orders -P 'sql=SELECT id, total FROM orders WHERE total > 100'"
Enter
Sleep 2.5s
Enter

# Step 2: PII table — DENIED
Type "# 2. Agent tries to access PII table"
Enter
Sleep 500ms
Type "agentfence check -p demo/policy.yaml -a analytics-bot -A query_data -P 'sql=SELECT * FROM users_pii'"
Enter
Sleep 2.5s
Enter

# Step 3: Denied field
Type "# 3. Agent tries to select credit card numbers"
Enter
Sleep 500ms
Type "agentfence check -p demo/policy.yaml -a analytics-bot -A query_data -P 'sql=SELECT name, credit_card_number FROM orders'"
Enter
Sleep 2.5s
Enter

# Step 4: Sneaky JOIN — the killer feature
Type "# 4. Sneaky JOIN to bypass table restrictions"
Enter
Sleep 500ms
Type "agentfence check -p demo/policy.yaml -a analytics-bot -A query_data -P 'sql=SELECT o.id FROM orders o JOIN payment_cards pc ON o.user_id = pc.user_id'"
Enter
Sleep 3s
Enter

# Step 5: Unknown agent — default deny
Type "# 5. Unknown agent = default deny (zero trust)"
Enter
Sleep 500ms
Type "agentfence check -p demo/policy.yaml -a rogue-agent -A anything"
Enter
Sleep 2.5s
Enter

# Closing
Type "# The tool name is allowed. The SQL content is not."
Enter
Type "# cargo install agentfence"
Enter
Sleep 3s
