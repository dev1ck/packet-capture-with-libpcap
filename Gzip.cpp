#include "Gzip.h"
#include <zlib.h>

namespace codec
{
    
#define SET_BINARY_MODE(file)
#define CHUNK 16384
#define WINDOW_BITS 15
#define GZIP_ENCODING 16


bool Gzip::Decompress(std::string_view compressedData, std::string& data)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK)
    {
        return false;
    }

    strm.avail_in = compressedData.size();
    strm.next_in = (unsigned char*)compressedData.data();
    do {
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                return false;
        }
        have = CHUNK - strm.avail_out;
        data.append((char*)out, have);
    } while (strm.avail_out == 0);

    if (inflateEnd(&strm) != Z_OK) {
        return false;
    }

    return true;
}

}
