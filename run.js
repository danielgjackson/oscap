const process = require('process');
const fs = require('fs');
const path = require('path');

const Pcap = require('./pcap');
const Osc = require('./osc');

const config = require('./config');

function filter(oscPacket) {
    if (oscPacket === null) return false;
    const allowed = config.allowList.length == 0 || config.allowList.map(re => oscPacket.address.match(re)).some(match => match !== null);
    const denied = config.denyList.length != 0 && config.denyList.map(re => oscPacket.address.match(re)).some(match => match !== null);
    return allowed && !denied;
}

function escape(value) {
    if (typeof value === 'undefined' || value === null) return '';
    if (typeof value === 'number') return value;
    const valueString = value.toString();
    if (!valueString.includes(',') && !valueString.includes('\"') && !valueString.includes('\r') && !valueString.includes('\n')) {
        return valueString;     // does not need quoting
    }
    return '"' + valueString.replace(/"/, '""') + '"';  // quoted
}

function processFile(filename, tabular) {
    const buffer = fs.readFileSync(filename);

    const basename = path.basename(filename, '.pcapng');

    const blocks = Pcap.parseBlocks(buffer.buffer);
    const packets = Pcap.extractPackets(blocks);

    const oscPackets = [];

    for (let packet of packets) {
        //Pcap.dumpPacket(packet);
        try {
            const ethernetPacket = Pcap.parseEthernet(packet);
            if (ethernetPacket !== null) {
                const ipPacket = Pcap.parseIp(ethernetPacket);
                if (ipPacket !== null) {
                    const udpPacket = Pcap.parseUdp(ipPacket);
                    if (udpPacket !== null) {
                        //Pcap.dumpUdp(udpPacket);
                        const oscPacket = Osc.parseOsc(udpPacket);
                        if (oscPacket !== null) {
                            oscPackets.push(oscPacket);
                        }
                    }
                }
            }
        } catch (e) {
            console.log(`WARNING: Problem parsing this packet: ${e}`);
        }
    }

    const oscAddresses = {};
    const sourceAddresses = {};
    const filtered = [];
    for (let oscPacket of oscPackets) {
        if (filter(oscPacket)) {
            if (!oscAddresses.hasOwnProperty(oscPacket.address)) {
                oscAddresses[oscPacket.address] = null;
            }
			if (!sourceAddresses.hasOwnProperty(oscPacket.udpPacket.ipPacket.source)) {
				sourceAddresses[oscPacket.udpPacket.ipPacket.source] = null;
			}
            filtered.push(oscPacket);
        } else {
        //    console.log(`IGNORING: ${oscPacket.address}${!allowed?' [not allowed]':''}${denied?' [denied]':''}`);
        }
    }

    // Use sorted array of headings and create a look-up for the column number
    const headings = Object.keys(oscAddresses).sort();
    for (let i in headings) {
        oscAddresses[headings[i]] = i;
    }
	
	const addresses = Object.keys(sourceAddresses).sort();
	for (let i in addresses) {
		sourceAddresses[addresses[i]] = i;
	}

	for (let address of addresses) {
		const lines = [];
		if (tabular) { // column headings
			const line = 'Time,Source,Dest,Address,Value,' + headings.map(h => escape(h)).join(',');
			lines.push(line);
			//console.log(line);
		}
		for (let oscPacket of filtered) {
			if (oscPacket.udpPacket.ipPacket.source !== address) { continue; }
			
			const result = {
				time: Osc.timestampString(oscPacket.udpPacket.ipPacket.ethPacket.packet.timestamp),
				source: oscPacket.udpPacket.ipPacket.source, // + ':' + oscPacket.udpPacket.sourcePort;
				dest: oscPacket.udpPacket.ipPacket.destination, // + ':' + oscPacket.udpPacket.destinationPort;
				address: oscPacket.address,
				params: oscPacket.params,
			};

			let value;
			if (result.params.length === 0) {
				value = null
			} else if (result.params.length === 1) {
				value = escape(result.params[0]);
			} else {
				value = escape(result.params.join(','));
			}

			// Add required column separators 
			const column = oscAddresses[result.address];
			const columnValue = ','.repeat(column) + value + ','.repeat(headings.length - column - 1);

			const line = `${result.time},${result.source},${result.dest},${result.address},${value}${tabular ? ',' + columnValue : ''}`;
			lines.push(line);
			//console.log(line);
		}
		
		const file = `${basename}-${address}.csv`;
		const filePath = path.join(path.dirname(filename), file);
		console.log(`WRITING: ${file} (${lines.length - (tabular ? 1 : 0)} packets)`);
		fs.writeFileSync(filePath, lines.join('\n'));
	}
}

const args = process.argv.slice(2);
if (args.length === 0) {
	console.log('ERROR: No .pcapng files specified');
} else {
	for (let filename of args) {
		processFile(filename, true);
	}
}
