/**
 * A focused EXIF reader.
 *
 * Not a general-purpose metadata library. It extracts the tags that identify a
 * person, a device, or a place -- which is the subset that matters when a photo
 * is about to be published, and the subset that is most often forgotten.
 *
 * The canonical failure is a photograph published from a phone with GPS enabled:
 * the visible image discloses nothing, and the file discloses the doorway it
 * was taken in. Redacting the pixels and shipping the EXIF is not redaction.
 */

/** One decoded metadata field. */
export interface ExifField {
  /** Human-readable tag name, or `Tag 0x829a` when unrecognised. */
  readonly name: string;
  /** Which directory it came from. */
  readonly ifd: 'IFD0' | 'EXIF' | 'GPS';
  readonly value: string;
  /** Numeric tag id, for callers that need to act on specific tags. */
  readonly tag: number;
}

/** Tags in the primary and thumbnail directories. */
const IFD0_TAGS: Readonly<Record<number, string>> = {
  0x010e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x013b: 'Artist',
  0x8298: 'Copyright',
  0x9c9b: 'XPTitle',
  0x9c9c: 'XPComment',
  0x9c9d: 'XPAuthor',
  0x9c9e: 'XPKeywords',
  0x9c9f: 'XPSubject',
  0x013c: 'HostComputer',
};

/** Tags in the EXIF sub-directory. */
const EXIF_TAGS: Readonly<Record<number, string>> = {
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x927c: 'MakerNote',
  0x9286: 'UserComment',
  0xa430: 'CameraOwnerName',
  0xa431: 'BodySerialNumber',
  0xa432: 'LensSpecification',
  0xa433: 'LensMake',
  0xa434: 'LensModel',
  0xa435: 'LensSerialNumber',
  0xa420: 'ImageUniqueID',
};

/** Tags in the GPS directory. */
const GPS_TAGS: Readonly<Record<number, string>> = {
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x0012: 'GPSMapDatum',
  0x001d: 'GPSDateStamp',
  0x001b: 'GPSProcessingMethod',
  0x001c: 'GPSAreaInformation',
};

/** Pointers to sub-directories, followed during the walk. */
const EXIF_IFD_POINTER = 0x8769;
const GPS_IFD_POINTER = 0x8825;

/** Bytes per component, indexed by TIFF type code. */
const TYPE_SIZES: Readonly<Record<number, number>> = {
  1: 1, // BYTE
  2: 1, // ASCII
  3: 2, // SHORT
  4: 4, // LONG
  5: 8, // RATIONAL
  7: 1, // UNDEFINED
  9: 4, // SLONG
  10: 8, // SRATIONAL
};

/**
 * Read a TIFF/EXIF block.
 *
 * `data` starts at the TIFF header (`II*\0` or `MM\0*`), which in a JPEG is the
 * six bytes after the `Exif\0\0` marker.
 *
 * Every read is bounds-checked and the directory walk is depth-limited.
 * Malformed EXIF is common -- from truncated uploads, from editors that rewrite
 * offsets badly, and from files deliberately crafted to trip parsers -- and a
 * reader that throws on any of it would refuse to scrub the files most in need
 * of scrubbing.
 */
export function readExif(data: Uint8Array): readonly ExifField[] {
  if (data.length < 8) return [];

  const byteOrder = (data[0]! << 8) | data[1]!;
  let littleEndian: boolean;
  if (byteOrder === 0x4949) littleEndian = true;
  else if (byteOrder === 0x4d4d) littleEndian = false;
  else return [];

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint16(2, littleEndian) !== 42) return [];

  const firstIfd = view.getUint32(4, littleEndian);
  const fields: ExifField[] = [];
  const visited = new Set<number>();

  walkIfd(view, data.length, firstIfd, littleEndian, 'IFD0', IFD0_TAGS, fields, visited, 0);
  return fields;
}

function walkIfd(
  view: DataView,
  length: number,
  offset: number,
  littleEndian: boolean,
  ifd: ExifField['ifd'],
  names: Readonly<Record<number, string>>,
  out: ExifField[],
  visited: Set<number>,
  depth: number,
): void {
  // A malformed file can point a directory at itself. Both guards are needed:
  // the visited set stops a cycle, the depth stops a long chain.
  if (depth > 4 || offset <= 0 || offset + 2 > length || visited.has(offset)) return;
  visited.add(offset);

  const count = view.getUint16(offset, littleEndian);
  const entriesEnd = offset + 2 + count * 12;
  if (entriesEnd > length) return;

  for (let i = 0; i < count; i++) {
    const entry = offset + 2 + i * 12;
    const tag = view.getUint16(entry, littleEndian);
    const type = view.getUint16(entry + 2, littleEndian);
    const componentCount = view.getUint32(entry + 4, littleEndian);

    if (tag === EXIF_IFD_POINTER || tag === GPS_IFD_POINTER) {
      const pointer = view.getUint32(entry + 8, littleEndian);
      const isGps = tag === GPS_IFD_POINTER;
      walkIfd(
        view,
        length,
        pointer,
        littleEndian,
        isGps ? 'GPS' : 'EXIF',
        isGps ? GPS_TAGS : EXIF_TAGS,
        out,
        visited,
        depth + 1,
      );
      continue;
    }

    const name = names[tag];
    if (name === undefined) continue;

    const value = readValue(view, length, entry, type, componentCount, littleEndian);
    if (value !== undefined && value.trim() !== '') {
      out.push({ name, ifd, value, tag });
    }
  }
}

function readValue(
  view: DataView,
  length: number,
  entry: number,
  type: number,
  count: number,
  littleEndian: boolean,
): string | undefined {
  const unitSize = TYPE_SIZES[type];
  if (unitSize === undefined || count === 0 || count > 0x10000) return undefined;

  const totalSize = unitSize * count;
  // Values of four bytes or fewer are stored inline in the offset field.
  const dataOffset = totalSize <= 4 ? entry + 8 : view.getUint32(entry + 8, littleEndian);
  if (dataOffset < 0 || dataOffset + totalSize > length) return undefined;

  switch (type) {
    case 2: {
      let out = '';
      for (let i = 0; i < count; i++) {
        const byte = view.getUint8(dataOffset + i);
        if (byte === 0) break;
        out += String.fromCharCode(byte);
      }
      return out;
    }
    case 1:
    case 7: {
      // Byte and undefined payloads are rendered as a size rather than content:
      // a MakerNote is thousands of opaque bytes, and printing them would be
      // noise, but its presence is worth reporting because it carries serial
      // numbers in several vendors' formats.
      return `<${count} bytes>`;
    }
    case 3:
      return String(view.getUint16(dataOffset, littleEndian));
    case 4:
      return String(view.getUint32(dataOffset, littleEndian));
    case 9:
      return String(view.getInt32(dataOffset, littleEndian));
    case 5:
    case 10: {
      const parts: string[] = [];
      for (let i = 0; i < Math.min(count, 3); i++) {
        const at = dataOffset + i * 8;
        const numerator =
          type === 5 ? view.getUint32(at, littleEndian) : view.getInt32(at, littleEndian);
        const denominator =
          type === 5 ? view.getUint32(at + 4, littleEndian) : view.getInt32(at + 4, littleEndian);
        parts.push(denominator === 0 ? '0' : String(numerator / denominator));
      }
      return parts.join(', ');
    }
    default:
      return undefined;
  }
}

/**
 * Convert a GPS coordinate triple to signed decimal degrees.
 *
 * EXIF stores magnitude and hemisphere separately, so a reader that ignores the
 * reference tag places every southern or western location in the wrong
 * hemisphere.
 */
export function gpsToDecimal(coordinate: string, ref: string): number | undefined {
  const parts = coordinate.split(',').map((p) => Number(p.trim()));
  if (parts.length < 2 || parts.some((p) => !Number.isFinite(p))) return undefined;
  const [degrees = 0, minutes = 0, seconds = 0] = parts;
  const magnitude = degrees + minutes / 60 + seconds / 3600;
  const negative = ref.toUpperCase().startsWith('S') || ref.toUpperCase().startsWith('W');
  return negative ? -magnitude : magnitude;
}
