// .pcapng File Parser

function toHex(value, length) {
	const str = value.toString(16).toUpperCase();
	return '0'.repeat(length > str.length ? length - str.length : 0) + str;
}

function macAddress(value) {
	return value.map(x => toHex(x, 2)).join(':');
}

function ipAddress(value) {
	return `${(value >>> 24) & 0xff}.${(value >>> 16) & 0xff}.${(value >>> 8) & 0xff}.${(value) & 0xff}`;
}

function timestampString(timestamp) {
	return timestamp.toISOString().replace('T', ' ').substring(0, 23);
}


function hexDump(dataView, offset, length) {
	const lines = [];
	const rowSize = 16;
	if (typeof offset === 'undefined') offset = 0;
	if (typeof length === 'undefined') length = dataView.byteLength - offset;
	const numRows = ((length + rowSize) / rowSize) | 0;
	for (let row = 0; row < numRows; row++) {
		const start = row * rowSize;
		const len = Math.min(length - start, 16);
		const addrStr = toHex(start, 4);	// +offset
		const bytes = new Array(len).fill(0).map((x, i) => dataView.getUint8(offset + start + i));
		let dumpBytes = bytes.map((x, i, arr) => toHex(x, 2) + (i % 4 === 3 ? '  ' : ' ')).join('');
		const width = rowSize * 3 + (rowSize / 4 | 0);
		if (width > dumpBytes.length) dumpBytes += ' '.repeat(width - dumpBytes.length);
		const dumpStr = bytes.map(x => x >= 32 && x < 128 ? String.fromCharCode(x) : '.').join('');
		line = `${addrStr}:  ${dumpBytes}  ${dumpStr}`;
		lines.push(line);
	}
	lines.map(line => console.log(line));
	return lines;
}

const BlockType = {
	SECTION_HEADER: 0x0a0d0d0a,		// Section Header Block SHB "\n\r\r\n"
	INTERFACE_DESCRIPTION: 0x01,	// Interface Description Block (IDB)
	SIMPLE_PACKET: 0x03,			// Simple Packet Block (SPB)
	NAME_RESOLUTION: 0x04,			// Name Resolution Block (NRB)
	INTERFACE_STATISTICS: 0x05,		// Interface Statistics Block (ISB)
	ENHANCED_PACKET: 0x06,			// Enhanced Packet Block (EPB)
}


class Pcap {

	static parseBlocks(arrayBuffer) {
		const dataView = new DataView(arrayBuffer);
		//console.log(`DATA: ${dataView.byteLength}`);		
		const blocks = [];
		for (let ofs = 0; ofs < dataView.byteLength;) {
			const blockType = dataView.getUint32(ofs, true);
			const blockLength = dataView.getUint32(ofs + 4, true);
			if (blockLength % 4 !== 0) {
				throw new Error(`ERROR: Block length not 32-bit aligned @${ofs} (${blockLength})`);
			}
			const blockLength2 = dataView.getUint32(ofs + blockLength - 4, true);
			if (blockLength2 != blockLength) {
				throw new Error(`ERROR: Block length check @${ofs + blockLength -4} (${blockLength2}) failed to match block starting @${ofs} (${blockLength})`);
			}
			const newBlock = {
				blockType,
				dataView: new DataView(dataView.buffer, dataView.byteOffset + ofs + 8, blockLength - 12),
				length: blockLength - 12,
				fileOffset: ofs,
				blockIndex: blocks.length,
			};
			blocks.push(newBlock);
			ofs += blockLength;
		}
		return blocks;
	}

	static extractPackets(blocks) {
		const packets = [];
		const interfaces = [];
		let interfaceId = 0;
		for (let block of blocks) {
			let type;
			switch (block.blockType) {
				case BlockType.SECTION_HEADER:
					type = 'SECTION_HEADER';
					// New section restarts the interface description
					interfaceId = 0;
					break;
				case BlockType.INTERFACE_DESCRIPTION:
					type = 'INTERFACE_DESCRIPTION';
					if (block.length < 20) {
						throw new Error(`ERROR: Interface Description Block length too small @${block.fileOffset} (${block.length})`);
					}

					const linkType = block.dataView.getUint16(8, true);
					const networkInterface = {
						interfaceId,
						linkType,	// LINKTYPE_ETHERNET=1, LINKTYPE_EXP_ETHERNET=2
						timestampSecondsPerTick: 10 ** -6,
					};

					// Parse options
					parse: for (let o = 16; o < block.length - 4; ) {
						const optionType = block.dataView.getUint16(o + 0, true);
						const optionLength = block.dataView.getUint16(o + 2, true);
						switch (optionType) {
							case 0:	// opt_endofopt
								o = block.length;
								break parse;
							case 1: // opt_comment
								break;
							case 9:	// if_tsresol
								const tsresol = block.dataView.getUint8(o + 4, true);
								if (tsresol & 0x80) {
									// positive power of 10
									networkInterface.timestampSecondsPerTick = 10 ** (tsresol & 0x7f);
								} else {
									// negative power of 10
									networkInterface.timestampSecondsPerTick = 10 ** -tsresol;
								}
								break;
							default:
								break;
						}
						o += 4 + 4 * (((optionLength + 3) / 4) | 0);
					}

					interfaces[networkInterface.interfaceId] = networkInterface;
					interfaceId++;
					break;
				case BlockType.SIMPLE_PACKET:
					type = 'SIMPLE_PACKET';
					console.error('WARNING: Simple packet found - these are not currently handled and this block will be ignored.')
					break;
				case BlockType.NAME_RESOLUTION:
					type = 'NAME_RESOLUTION';
					break;
				case BlockType.INTERFACE_STATISTICS:
					type = 'INTERFACE_STATISTICS';
					break;
				case BlockType.ENHANCED_PACKET:
					{
						type = 'ENHANCED_PACKET';
						if (block.length < 32) {
							throw new Error(`ERROR: Enhanced Packet Block length too small @${block.fileOffset} (${block.length})`);
						}
						const interfaceId = block.dataView.getUint32(0, true);
						const timestampHigh = block.dataView.getUint32(4, true);
						const timestampLow = block.dataView.getUint32(8, true);
						const capturedPacketLength = block.dataView.getUint32(12, true);
						const originalPacketLength = block.dataView.getUint32(16, true);
						const packetDataOffset = 20;
						const optionsOffset = packetDataOffset + (4 * ((capturedPacketLength + 3) / 4 | 0));
						const optionsLength = block.length - 4 - optionsOffset;

						// Network interface
						const networkInterface = interfaces[interfaceId];
						let timestampSecondsPerTick = 10 ** -6;	// default is microseconds
						if (networkInterface && networkInterface.timestampSecondsPerTick) {
							timestampSecondsPerTick = networkInterface.timestampSecondsPerTick;
						}

						// Timestamp
						const timestampRaw = (timestampHigh * 2**32) + timestampLow;	// time since 1970, units specified in Interface Description Block
						const timestamp = new Date(timestampRaw * timestampSecondsPerTick * 1000);

						// TODO: Should take the LinkType from the interface description block to be able to parse the link layer headers
						// -- should only include IP packets over Ethernet
						const newPacket = {
							block,
							networkInterface,
							timestamp,
							originalPacketLength,
							dataView: new DataView(block.dataView.buffer, block.dataView.byteOffset + packetDataOffset, capturedPacketLength),
							length: capturedPacketLength,
							packetIndex: packets.length,
						};
						packets.push(newPacket);

						if (optionsLength > 0) {
							//console.log(`...OPTIONS: <${optionsLength}>`)
							//hexDump(block.dataView, optionsOffset, optionsLength);
						}
					}
					break;
				default:
					type = '<unknown>';
					break;
			}
			
			//console.log(`BLOCK: #${count}, @${ofs}, type 0x${toHex(blockType, 8)}=${type}, length ${blockLength}`);			
		}
		return packets;
	}

	static dumpPacket(packet) {
		console.log(`PACKET: #${packet.packetIndex} @${timestampString(packet.timestamp)} <${packet.length}/${packet.originalPacketLength}>`)
		hexDump(packet.dataView, 0, packet.length);
	}

	static parseEthernet(packet) {
		if (!packet.networkInterface || (packet.networkInterface.linkType !== 1 && packet.networkInterface.linkType !== 2)) {
			console.error('WARNING: Packet from an unknown interface, or an interface with an unknown (non-Ethernet) LinkType - this packet will be ignored.')
			return null;
		}

		// Ethernet (14-byte Ethernet frame)
		// @0  <6> destination host address
		// @6  <6> source host address
		// @12 <2> ethernet (type 0x0800 = IPv4, 0x86DD = IPv6)
		const destinationHost = new Array(6);
		for (let i = 0; i < destinationHost.length; i++) { destinationHost[i] = packet.dataView.getUint8(0 + i); }
		const sourceHost = new Array(6);
		for (let i = 0; i < sourceHost.length; i++) { sourceHost[i] = packet.dataView.getUint8(6 + i); }
		const etherType = packet.dataView.getUint16(12, false);

		return {
			packet,
			destinationHost,
			destinationMac: macAddress(destinationHost),
			sourceHost,
			sourceMac: macAddress(sourceHost),
			etherType,
			dataView: new DataView(packet.dataView.buffer, packet.dataView.byteOffset + 14, packet.dataView.byteLength - 14),
		};
	}

	static parseIp(ethPacket) {
		// Internet Protocol (IP)
		// Only IPv4 for now...
		if (ethPacket.etherType !== 0x0800) {	// IPv4
			if (ethPacket.etherType === 0x86DD) {	// IPv6
				console.error('WARNING: IPv6 packet found - these are not currently handled (only IPv4) and this packet will be ignored.')
			}
			return null;
		}
		
		// Internet Protocol (IP)
		// @0 <1> version (4-bits) and header length (4-bits)
		// @1 <1> service type
		// @2 <2> total length
		// @4 <2> identification
		// @6 <2> flags (3 bits) and fragment offset (13-bits)
		// @8 <1> time-to-live
		// @9 <1> type (0x11=UDP, 0x06=TCP)
		// @10 <2> header checksum
		// @12 <4> source address
		// @16 <4> destination address
		// @20 <optionLen> (0-40 bytes)
		const version = ethPacket.dataView.getUint8(0) >>> 4;	
		const headerLength = ethPacket.dataView.getUint8(0) & 0xf;	// DWORDs	
		//const serviceType = ethPacket.dataView.getUint8(1);
		const totalLength = ethPacket.dataView.getUint16(2, false);	
		//const identification = ethPacket.dataView.getUint16(4, false);	
		//const flagsOffset = ethPacket.dataView.getUint16(6, false);	
		//const timeToLive = ethPacket.dataView.getUint8(8);	
		const type = ethPacket.dataView.getUint8(9);			// 0x11 = UDP, 0x06 = TCP
		const headerChecksum = ethPacket.dataView.getUint16(10, false);	
		const sourceAddress = ethPacket.dataView.getUint32(12, false);	
		const destinationAddress = ethPacket.dataView.getUint32(16, false);	

		if (version != 4) {
			throw new Error(`ERROR: Invalid IP packet version (${version})`);
		}
		if (headerLength * 4 < 20) {
			throw new Error(`ERROR: Invalid IP packet length (${headerLength * 4})`);
		}
		const optionLen = headerLength * 4 - 20;

		if (totalLength > ethPacket.dataView.byteLength) {
			throw new Error(`NOTE: IP packet length ${totalLength} larger than data length ${ethPacket.dataView.byteLength}`);
		}
		if (totalLength < ethPacket.dataView.byteLength) {
			//Pcap.dumpPacket(ethPacket.packet);
			//console.log(`NOTE: IP packet length ${totalLength} shorter than data length ${ethPacket.dataView.byteLength}`);
		}

		const ipPacket = {
			ethPacket,
			type,
			sourceAddress,
			totalLength,
			source: ipAddress(sourceAddress),
			destinationAddress,
			destination: ipAddress(destinationAddress),
			dataView: new DataView(ethPacket.dataView.buffer, ethPacket.dataView.byteOffset + 20 + optionLen, ethPacket.dataView.byteLength - 20 - optionLen),
		};

		return ipPacket;
	}

	static parseUdp(ipPacket) {
		if (ipPacket.type !== 0x11) {	// UDP
			return null;
		}

		// UDP
		// @0 <2> UDP: source port
		// @2 <2> UDP: destination port
		// @4 <2> UDP: length (including header)
		// @6 <2> UDP: checksum
		// @8     Payload
		const sourcePort = ipPacket.dataView.getUint16(0, false);
		const destinationPort = ipPacket.dataView.getUint16(2, false);
		const lengthHeaderAndData = ipPacket.dataView.getUint16(4, false);
		const checksum = ipPacket.dataView.getUint16(6, false);

		if (lengthHeaderAndData < 8) {
			throw new Error(`ERROR: Invalid UDP packet length (${lengthHeaderAndData})`);
		}

		if (lengthHeaderAndData > ipPacket.dataView.byteLength) {
			throw new Error(`ERROR: UDP length ${lengthHeaderAndData} greater than packet length ${ipPacket.dataView.byteLength}`);
		}
		
		if (lengthHeaderAndData != ipPacket.dataView.byteLength) {
			//Pcap.dumpPacket(ipPacket.ethPacket.packet);
			//console.log(`NOTE: UDP length ${lengthHeaderAndData} shorter than packet length ${ipPacket.dataView.byteLength}`);
		}

		const udpPacket = {
			ipPacket,
			sourcePort,
			destinationPort,
			length: lengthHeaderAndData - 8,
			checksum,
			dataView: new DataView(ipPacket.dataView.buffer, ipPacket.dataView.byteOffset + 8, ipPacket.dataView.byteLength - 8),
		};

		return udpPacket;
	}

	static dumpUdp(udpPacket) {
		const time = timestampString(udpPacket.ipPacket.ethPacket.packet.timestamp);
		const source = udpPacket.ipPacket.source + ':' + udpPacket.sourcePort;
		const dest = udpPacket.ipPacket.destination + ':' + udpPacket.destinationPort;
		console.log(`UDP: @${time} ${source} --> ${dest} <${udpPacket.length}>`);
		hexDump(udpPacket.dataView, 0, udpPacket.dataView.byteLength);
	}

}

module.exports = Pcap;
