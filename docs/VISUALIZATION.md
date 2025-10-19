# State Visualization

AWS Security Watch includes a powerful visualization tool that generates interactive node-based diagrams of your monitored infrastructure.

## Quick Start

```bash
# Auto-detect state file (works if you have one account)
python3 visualize_state.py

# Specify account ID
python3 visualize_state.py --account-id 123456789012

# Watch mode - auto-regenerates when state changes
python3 visualize_state.py --watch

# Specify custom state file path
python3 visualize_state.py --state-file state/123456789012.json

# For graphical visualization (optional):
pip install graphviz watchdog
# Install Graphviz software:
# macOS: brew install graphviz
# Ubuntu: sudo apt-get install graphviz
# Windows: Download from https://graphviz.org/download/
```

## Two Visualization Modes

### 1. Text-Based (Default - No Dependencies)
Works out of the box with no additional installations. Uses Unicode box drawing characters and emojis for a clean, readable output in your terminal.

### 2. Graphical (Optional - Requires Graphviz)
Generates PNG/SVG/PDF diagrams with nodes and edges when graphviz is installed.

## Features

### 🎨 Color-Coded Nodes
Each resource type has a distinct color matching AWS branding:
- **CloudTrail** - Orange (#FF9900)
- **S3** - Green (#569A31)
- **SQS** - Pink (#FF4F8B)
- **SNS** - Yellow (#D9A741)
- **Lambda** - Orange (#FF9900)
- **IAM** - Red (#DD344C)
- **GuardDuty** - Green (#759C3E)
- **EventBridge** - Magenta (#E7157B)

### 🔗 Relationship Arrows
The diagram shows connections between resources:
- CloudTrail → S3 (logs to)
- S3 → SNS/SQS/Lambda (event notifications)
- Lambda → IAM (assumes role)
- SNS → SQS (subscriptions)

### 📊 Resource Metadata
Nodes display key information:
- **CloudTrail**: Logging status (🟢 Logging / 🔴 Stopped)
- **S3**: Encryption status (🔒), bucket size
- **SQS**: Encryption status (🔒)
- **SNS**: Encryption status (🔒)
- **Lambda**: Runtime version
- **IAM**: Policy counts (managed + inline)
- **GuardDuty**: Status, filter count
- **EventBridge**: Rule state (🟢 Enabled / 🔴 Disabled)

### 🌎 Regional Clustering
Resources are grouped by AWS region for better organization.

### 🔄 Auto-Update Mode
Watch mode monitors the state file and regenerates the visualization whenever changes are detected.

## Command-Line Options

```bash
# Auto-detect from state directory (default: state/)
python3 visualize_state.py

# Specify account ID
python3 visualize_state.py --account-id 123456789012

# Specify custom state directory
python3 visualize_state.py --state-dir /path/to/state

# Specify exact state file path
python3 visualize_state.py --state-file state/123456789012.json

# Change output format (requires graphviz)
python3 visualize_state.py --format svg    # or pdf, png

# Custom output filename
python3 visualize_state.py --output infrastructure_map

# Watch mode with custom interval
python3 visualize_state.py --watch --interval 10
```

## Usage Examples

### One-Time Generation
```bash
python3 visualize_state.py
# Generates: state_diagram.png
```

### SVG Output
```bash
python3 visualize_state.py --format svg --output my_infrastructure
# Generates: my_infrastructure.svg
```

### Live Monitoring
```bash
python3 visualize_state.py --watch
# Watches state.json and regenerates on changes
# Press Ctrl+C to stop
```

## Integration with Monitoring

Run the visualization in watch mode alongside your monitoring script:

```bash
# Terminal 1 - Run monitoring
python3 aws_security_watch.py --profile my-profile

# Terminal 2 - Watch and visualize
python3 visualize_state.py --watch
```

Every time the monitoring script detects changes and updates `state.json`, the visualization will automatically regenerate.

## Output Formats

### PNG (Default)
Best for quick viewing and sharing. Works everywhere.

### SVG
Vector format, scales perfectly. Great for documentation and web.

### PDF
Professional output for reports and presentations.

## Example Output

### Text-Based Visualization
```
┌──────────────────────────────────────────────────────────────────────────────┐
│        AWS Security Watch State - Updated: 2025-10-18T12:30:00Z             │
└──────────────────────────────────────────────────────────────────────────────┘

─── Region: us-east-1 ──────────────────────────────────────────────────────────
  📋 CloudTrail: prod-trail
     • Status: 🟢 Logging
     • Multi-region: Yes
     → logs to → prod-logs

  🪣 S3 Bucket: prod-logs
     • 🔒 Encrypted
     • Size: 15.3 GB
     • Objects: 12543
     → notifies → SNS: cloudtrail-alerts

  📢 SNS Topic: cloudtrail-alerts
     • 🔒 Encrypted
     • Subscriptions: 2

  λ Lambda: log-processor
     • Runtime: python3.11
     • Memory: 512 MB
     → assumes → IAM: LogProcessorRole

─── IAM Roles (Global) ─────────────────────────────────────────────────────────
  🔐 IAM Role: LogProcessorRole
     • Managed policies: 2
     • Inline policies: 1

─── Summary ────────────────────────────────────────────────────────────────────

  📋 Cloudtrail: 1
  🪣 S3: 1
  📢 Sns: 1
  λ Lambda: 1
  🔐 Iam: 1

  Total resources monitored: 5
```

### Graphical Visualization (with graphviz)
Generates a professional diagram with colored nodes and relationship arrows saved as PNG/SVG/PDF.

## Troubleshooting

### "graphviz module not found"
```bash
pip install graphviz
```

### "Graphviz software not found"
Install the Graphviz software (not just the Python package):
- macOS: `brew install graphviz`
- Ubuntu: `sudo apt-get install graphviz`
- Windows: https://graphviz.org/download/

### "watchdog module not found"
```bash
pip install watchdog
```

Note: If watchdog is not installed, the script will fall back to polling mode which still works but is less efficient.

### Empty diagram
Make sure your `state.json` file exists and contains monitored resources. Run the monitoring script first:
```bash
python3 aws_security_watch.py --profile my-profile
```

## Tips

1. **Use watch mode** during testing to see infrastructure changes in real-time
2. **SVG format** is best for embedding in documentation
3. **PDF format** is best for sharing with stakeholders
4. **Run visualization on a separate screen** while monitoring to see live updates
5. **Customize colors** by editing the `COLORS` dictionary in `visualize_state.py`
