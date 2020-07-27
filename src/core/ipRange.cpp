/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ipRange.h"

// https://stackoverflow.com/questions/57276005/how-to-find-whether-a-given-ipv6-address-falls-in-the-cidr-range-using-c-or-c
// https://stackoverflow.com/a/57288759/3548568


boost::asio::ip::address_v4_range getRange(boost::asio::ip::address_v4 address, size_t size) {
    boost::asio::ip::address_v4 end = boost::asio::ip::address_v4(
            (address.to_ulong() + (1 << (32 - size))) & 0xFFFFFFFF);
    return boost::asio::ip::address_v4_range(address, end);
}

boost::asio::ip::address_v6_range getRange(boost::asio::ip::address_v6 address, size_t size) {
    auto bytes = address.to_bytes();
    size_t offset = size >> 3;
    uint8_t toAdd = 1 << (8 - (size & 0x7));
    while (toAdd) {
        int value = bytes[offset] + toAdd;
        bytes[offset] = value & 0xFF;
        toAdd = value >> 8;
        if (offset == 0) {
            break;
        }
        offset--;
    }
    boost::asio::ip::address_v6 end = boost::asio::ip::address_v6(bytes);
    return boost::asio::ip::address_v6_range(address, end);
}

template<typename Addr>
bool parseAddress(const std::string &str, Addr &addr) {
    boost::system::error_code ec;
    addr = Addr::from_string(str, ec);
    return !ec;
}

template<typename Addr>
bool parseRange(const std::string &str, boost::asio::ip::basic_address_range<Addr> &range) {
    size_t pos = str.find('/');
    if (pos == std::string::npos) {
        return false;
    }
    // should only be one slash
    if (str.find('/', pos + 1) != std::string::npos) {
        return false;
    }
    Addr address;
    if (!parseAddress(str.substr(0, pos), address)) {
        return false;
    }
    std::string sizeStr = str.substr(pos + 1);
    size_t index;
    int size = std::stoi(sizeStr, &index);
    if (index != sizeStr.size()) {
        return false;
    }
    if (size > std::tuple_size<typename Addr::bytes_type>::value * 8 || size < 0) {
        return false;
    }
    range = getRange(address, size);
    return true;
}

//template<>
//bool parseRange<boost::asio::ip::address_v4>(
//        const std::string &str,
//        boost::asio::ip::basic_address_range<boost::asio::ip::address_v4> &range);
//
//template<>
//bool parseRange<boost::asio::ip::address_v6>(
//        const std::string &str,
//        boost::asio::ip::basic_address_range<boost::asio::ip::address_v6> &range);


bool parseRangeV4(const std::string &str, boost::asio::ip::address_v4_range &range) {
    return parseRange(str, range);
}

bool parseRangeV6(const std::string &str, boost::asio::ip::address_v6_range &range) {
    return parseRange(str, range);
}


//int main2() {
//    boost::asio::ip::address_v6 address;
//    if (!parseAddress("2001:4860:4860:0000:0000:0000:012D:8888", address)) {
//        std::cout << "invalid address\n";
//        return 1;
//    }
//    boost::asio::ip::address_v6_range range;
//    if (!parseRange("2001:4860:4860:0000:0000:0000:0000:8888/32", range)) {
//        std::cout << "invalid range\n";
//        return 1;
//    }
//    bool inRange = range.find(address) != range.end();
//    std::cout << "in range: " << inRange << "\n";
//    return 0;
//}
