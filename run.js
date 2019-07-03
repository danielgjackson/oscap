const process = require('process');
const fs = require('fs');
const path = require('path');

const Pcap = require('./pcap');
const Osc = require('./osc');

const allowList = require('./filter-allow');
const denyList = require('./filter-deny');

function processFile(filename) {
    const buffer = fs.readFileSync(filename);

    const pcap = new Pcap();
    const osc = new Osc();
    const blocks = pcap.parseBlocks(buffer.buffer);
    const packets = pcap.extractPackets(blocks);

    for (let packet of packets) {
        //pcap.dumpPacket(packet);
        try {
            const ethernetPacket = pcap.parseEthernet(packet);
            if (ethernetPacket !== null) {
                const ipPacket = pcap.parseIp(ethernetPacket);
                if (ipPacket !== null) {
                    const udpPacket = pcap.parseUdp(ipPacket);
                    if (udpPacket !== null) {
                        //pcap.dumpUdp(udpPacket);
                        const oscPacket = osc.parseOsc(udpPacket);
                        if (oscPacket !== null) {

                            const allowed = allowList.length == 0 || allowList.map(re => oscPacket.address.match(re)).some(match => match !== null);
                            const denied = denyList.length != 0 && denyList.map(re => oscPacket.address.match(re)).some(match => match !== null);

                            if (allowed && !denied) {
                                osc.dumpOsc(oscPacket);
                            } else {
//                                console.log(`IGNORING: ${oscPacket.address}${!allowed?' [not allowed]':''}${denied?' [denied]':''}`);
                            }
                        }
                    }
                }
            }
        } catch (e) {
            console.log(`WARNING: Problem parsing this packet: ${e}`);
        }
    }
}

const args = process.argv.slice(2);
if (args.length === 0) {
	console.log('ERROR: No .pcapng files specified');
} else {
	for (let filename of args) {
		processFile(filename);
	}
}
