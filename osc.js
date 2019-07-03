// OSC (Subset) Parser

const { TextDecoder } = require('util');

function toHex(value, length) {
	const str = value.toString(16).toUpperCase();
	return '0'.repeat(length > str.length ? length - str.length : 0) + str;
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
	static timestampString(timestamp) {
		return timestamp.toISOString().replace('T', ' ').substring(0, 23);
	}
	
	static dumpState(state, message) {
		console.log(`WARNING: ${message} - at offset ${state.offset} of ${state.dataView.byteLength}`);
		hexDump(state.dataView, 0, state.dataView.byteLength);
	}

	static readPadding(state) {
		// 32-bit aligned
		while (state.offset % 4 !== 0) {
			if (state.offset >= state.dataView.byteLength || state.dataView.getUint8(state.offset) !== 0) {
				//this.dumpState(state, 'Padding malformed');
				const error = new Error('ERROR: Padding malformed.');
				error.malformed = true;
				throw error;
			}
			state.offset++;
		}
	}

	static readInt(state) {
		const value = state.dataView.getInt32(state.offset, false);
		state.offset += 4;
		return value;
	}

	static readUint(state) {
		const value = state.dataView.getUint32(state.offset, false);
		state.offset += 4;
		return value;
	}

	static readLong(state) {
		const value = state.dataView.getInt64(state.offset, false);
		state.offset += 8;
		return value;
	}

	static readFloat(state) {
		const value = state.dataView.getFloat32(state.offset, false);
		state.offset += 4;
		return value;
	}

	static readDouble(state) {
		const value = state.dataView.getFloat64(state.offset, false);
		state.offset += 8;
		return value;
	}

	static readString(state) {
		for (const initialOffset = state.offset; state.offset < state.dataView.byteLength; state.offset++) {
			const c = state.dataView.getUint8(state.offset);
			if (c === 0) {
				const stringDataView = new DataView(state.dataView.buffer, state.dataView.byteOffset + initialOffset, state.offset - initialOffset);
				state.offset++;
				this.readPadding(state);
				return new TextDecoder().decode(stringDataView);
			}
		}
		const error = new Error('ERROR: End of string not found.');
		error.malformed = true;
		throw error;
}
	
	static readBlob(state) {
		const size = this.readInt(state);
		const dataView = new DataView(state.dataView.buffer, state.dataView.byteOffset + state.offset, size);
		state.offset += size;
		this.readPadding(state);
		return dataView;
	}

	static parseOsc(udpPacket) {
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
				const error = new Error(`ERROR: OSC TypeTag does not start with comma -- ignoring packet: ${typeTag}`);
				error.malformed = true;
				throw error;
			}

			const params = [];
			for (let i = 1; i < typeTag.length; i++) {
				const type = typeTag[i];
				switch (type) {
					case 'i':	// int32
						params.push(this.readInt(state));
						break;
					case 'f':	// float
						params.push(this.readFloat(state));
						break;
					case 's':	// string
						params.push(this.readString(state));
						break;
					case 'b':	// blob
						params.push(this.readBlob(state));
						break;
					case 'h':	// int64
						params.push(this.readLong(state));
						break;
					case 't':	// OSC-timetag (int64)
						const timestamp = this.readLong(state);
						const timestamp1900Seconds = (timestamp >>> 32) + ((timestamp & 0xFFFFFFFF) / 0x100000000);
						const epoch1900to1970Seconds = 2208988800;
						const timestamp1970Milliseconds = (epoch1900to1970Seconds + timestamp1900Seconds) * 1000;
						params.push(timestamp1970Milliseconds);
						break;
					case 'd':	// double
						params.push(this.readDouble(state));
						break;
					case 'S':	// symbol (string)
						params.push(this.readString(state));
						break;
					case 'c':	// character (uint32)
						params.push(String.fromCodePoint(this.readUint(state)));
						break;
					case 'r':	// RGBA color (uint32)
						params.push(this.readUint(state));
						break;
					case 'm':	// 4-byte MIDI message (uint32)
						params.push(this.readUint(state));
						break;
					case 'T':	// true (true)
						params.push(true);
						break;
					case 'F':	// false (false)
						params.push(false);
						break;
					case 'N':	// nill (null)
						params.push(null);
						break;
					case 'I':	// infinitum (null)
						params.push(null);
						break;
					case '[':	// array start
					case ']':	// array end
						console.log(`WARNING: OSC arrays '${type}' not currently handled - following parameters may be corrupt or incomplete`)
						params.push(null);
						break;
					default:
						console.log(`WARNING: OSC type '${type}' not currently handled - following parameters may be corrupt or incomplete`)
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
			if (!e.malformed)		// Ignore malformed errors (as this just won't successfully parse as an OSC packet)
				console.error(`ERROR: While trying to parse UDP packet as OSC: ${e.message}`);
			return null;
		}
	}
	
	static dumpOsc(oscPacket) {
		const time = Osc.timestampString(oscPacket.udpPacket.ipPacket.ethPacket.packet.timestamp);
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
