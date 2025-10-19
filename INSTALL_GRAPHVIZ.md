# Installing Graphviz for Visualization

The `visualize_state.py` script works in **two modes**:

1. **Text-based** (default) - No installation needed
2. **Graphical** (optional) - Requires both Python module + software

## Quick Start (Text Mode)

**No installation needed!** Just run:
```bash
python3 visualize_state.py
```

The script will automatically use text-based visualization with Unicode characters and emojis.

## Installing Graphviz for Graphical Output

For PNG/SVG/PDF diagram output, you need **both**:

### 1. Python Module

```bash
pip install graphviz
```

### 2. Graphviz Software

The Python module is just a wrapper - you also need the actual Graphviz software:

#### Ubuntu/Debian (WSL)
```bash
sudo apt-get update
sudo apt-get install graphviz
```

#### macOS
```bash
brew install graphviz
```

#### Windows
1. Download from https://graphviz.org/download/
2. Run the installer
3. Add to PATH (installer should do this automatically)

## Verify Installation

After installing both, verify it works:

```bash
# Check Python module
python3 -c "import graphviz; print('Python module OK')"

# Check Graphviz software
dot -V
```

Expected output:
```
Python module OK
dot - graphviz version X.X.X (...)
```

## Troubleshooting

### Error: "graphviz module not found"
**Solution:** Install Python module
```bash
pip install graphviz
```

### Error: "Graphviz software not found" or "dot command not found"
**Solution:** Install Graphviz software (see platform-specific instructions above)

### Still not working on Windows?
1. Check PATH includes Graphviz bin directory
2. Restart terminal/command prompt
3. Try: `where dot` to verify it's in PATH
4. Manual PATH: `C:\Program Files\Graphviz\bin`

### On WSL (Windows Subsystem for Linux)?
Use the Ubuntu/Debian instructions, not Windows instructions.

## Alternative: Use Text Mode

If you don't want to install Graphviz, the text-based visualization works perfectly:

```bash
# Just run without graphviz
python3 visualize_state.py

# Example output:
┌────────────────────────────────────────┐
│  AWS Security Watch State              │
└────────────────────────────────────────┘

─── Region: us-east-1 ──────────────────
  📋 CloudTrail: my-trail
     • Status: 🟢 Logging
     → logs to → my-bucket

  🪣 S3 Bucket: my-bucket
     • 🔒 Encrypted
     • Size: 15.3 GB
```

## Which Mode Should I Use?

| Feature | Text Mode | Graphical Mode |
|---------|-----------|----------------|
| Installation | ✓ None needed | ✗ Requires 2 packages |
| Platform | ✓ All platforms | ✓ All platforms |
| Output | Terminal only | PNG/SVG/PDF files |
| Resource info | ✓ Full details | ✓ Full details |
| Relationships | ✓ Shows arrows | ✓ Visual graph |
| Best for | Quick checks, SSH sessions | Reports, documentation |

**Recommendation:** Start with text mode, install graphviz only if you need file output.
