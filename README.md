# oscap

Open Sound Control (OSC) packet extraction from .PCAPNG files.

# Usage

```bash
node run $INPUT_FILENAME.pcapng | tee $OUTPUT_FILENAME.csv
```

# Filters

Edit `config.js` to filter which OSC addresses are used: `filterDeny` for regular expressions for OSC addresses to ignore, `filterAllow` for regular expressions for OSC addresses to include (if allow is empty, all are allowed; deny wins if both match).

# To do

* Output option to tabulate changes (one column per address) for use in a spreadsheet.
