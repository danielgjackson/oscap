// OSC (Subset) Parser

const { TextDecoder } = require('util');

function toHex(value, length) {
	const str = value.toString(16).toUpperCase();
	return '0'.repeat(length > str.length ? length - str.length : 0) + str;
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

function isPlain(text) {
	for (let i = 0; i < text.length; i++) {
		const c = text.charCodeAt(i);
		if (c < 32 || c > 127) return false;
	}
	return true;
}

class Osc {

	constructor() {
	}

	dumpState(state, message) {
		console.log(`WARNING: ${message} - at offset ${state.offset} of ${state.dataView.byteLength}`);
		hexDump(state.dataView, 0, state.dataView.byteLength);
	}

	readPadding(state) {
		// 32-bit aligned
		while (state.offset % 4 !== 0) {
			if (state.offset >= state.dataView.byteLength || state.dataView.getUint8(state.offset) !== 0) {
				//this.dumpState(state, 'Padding malformed');
				const error = new Error("ERROR: Padding malformed.");
				error.isPadding = true;
				throw error;
			}
			state.offset++;
		}
	}

	readInt(state) {
		const value = state.dataView.getUint32(state.offset, false);
		state.offset += 4;
		return value;
	}

	readFloat(state) {
		const value = state.dataView.getFloat32(state.offset, false);
		state.offset += 4;
		return value;
	}

	readString(state) {
		for (const initialOffset = state.offset; state.offset < state.dataView.byteLength; state.offset++) {
			const c = state.dataView.getUint8(state.offset);
			if (c === 0) {
				const stringDataView = new DataView(state.dataView.buffer, state.dataView.byteOffset + initialOffset, state.offset - initialOffset);
				state.offset++;
				this.readPadding(state);
				return new TextDecoder().decode(stringDataView);
			}
		}
		throw new Error("ERROR: End of string not found.");
	}
	
	readBlob(state) {
		const size = this.readInt(state);
		const dataView = new DataView(state.dataView.buffer, state.dataView.byteOffset + state.offset, size);
		state.offset += size;
		this.readPadding(state);
		return dataView;
	}

	parseOsc(udpPacket) {
		try {
			const state = {
				dataView: udpPacket.dataView,
				offset: 0,
			}

			const address = this.readString(state);

			if (address === '#bundle') {
				console.log('WARNING: OSC Bundles not yet supported -- ignoring.');
				return null;
			}

			// if (!address.startsWith('/')) {
			// 	console.log(`WARNING: OSC Address does not start with slash -- ignoring: ${address}`);
			//  return null;
			// }

			if (address.length == 0 || !isPlain(address)) {
				//console.log(`WARNING: OSC Address is not plain ASCII and unlikely to be a real OSC address -- ignoring.`)
				//this.dumpState(state, 'Address');
				return null;
			}

			const typeTag = this.readString(state);
			
			if (!typeTag.startsWith(',')) {
				console.log(`WARNING: OSC TypeTag does not start with comma -- ignoring: ${typeTag}`)
				return null;
			}

			const params = [];
			for (let i = 1; i < typeTag.length; i++) {
				const type = typeTag[i];
				switch (type) {
					case 's':
						params.push(this.readString(state));
						break;
					case 'i':
						params.push(this.readInt(state));
						break;
					case 'f':
						params.push(this.readFloat(state));
						break;
					case 'b':
						params.push(this.readBlob(state));
						break;
					default:
						console.log(`WARNING: OSC type '${type}' not handled - following parameters may be corrupt`)
						params.push(null);
						break;
				}
			}

			const oscPacket = {
				udpPacket,
				address,
				typeTag,
				params,
			};
			return oscPacket;
		} catch (e) {
			if (!e.isPadding)
				console.error(e.message);
			return null;
		}
	}
	
	dumpOsc(oscPacket) {
		const time = timestampString(oscPacket.udpPacket.ipPacket.ethPacket.packet.timestamp);
		const source = oscPacket.udpPacket.ipPacket.source; // + ':' + oscPacket.udpPacket.sourcePort;
		const dest = oscPacket.udpPacket.ipPacket.destination; // + ':' + oscPacket.udpPacket.destinationPort;
		console.log(`${time},${source},${dest},${oscPacket.address},` + oscPacket.params.map(x => ''+x).join(','));
		// for (let i = 0; i < oscPacket.params.length; i++) {
		// 	console.log(`...[${i}] = ${oscPacket.params[i]}`);
		// 	if (oscPacket.params[i] instanceof DataView) {
		// 		hexDump(oscPacket.params[i]);
		// 	}
		// }
		//hexDump(oscPacket.udpPacket.dataView, 0, oscPacket.udpPacket.dataView.byteLength);
	}

}

module.exports = Osc;
