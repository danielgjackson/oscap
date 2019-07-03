# oscap

Open Sound Control (OSC) packet extraction from .PCAPNG files.

# Usage

```bash
node run $INPUT_FILENAME.pcapng | tee $OUTPUT_FILENAME.csv
```

Each OSC packet creates a row of the output containing:

> Time,Source,Dest,Address,Value

Each of the different addresses will form an additional column and the value will be replicated in the column for the current address -- this allows for easy plotting in a spreadsheet.

# Filters

Edit `config.js` to filter which OSC addresses are used: `filterDeny` for regular expressions for OSC addresses to ignore, `filterAllow` for regular expressions for OSC addresses to include (if allow is empty, all are allowed; deny wins if both match).

