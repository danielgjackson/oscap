# oscap

Open Sound Control (OSC) packet extraction from .PCAPNG files.

# Usage

```bash
node run $INPUT_FILENAME.pcapng | tee $OUTPUT_FILENAME.csv
```

# Filters

Edit `filter-allow.js` with regular expressions for OSC addresses to use.  Edit `filter-deny.js` with regular expressions for OSC addresses to ignore.  Deny wins if both match.  If allow is empty, all are allowed (unless denied).

# To do

* Output option to tabulate changes (one column per address) for use in a spreadsheet.
