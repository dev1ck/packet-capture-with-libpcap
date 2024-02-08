#ifndef __CODEC__GZIP_H__
#define __CODEC__GZIP_H__

#include <string>
#include <string_view>

namespace codec
{

class Gzip
{
public:
  // GZip Decompression
  // @param compressedData - the gzip compressed data
  // @param data - the resulting uncompressed data (may contain binary data)
  // @return - true on success, false on failure
  static bool Decompress(std::string_view compressedData, std::string& data);
};

}

#endif /* end of include guard: __CODEC__GZIP_H__ */
