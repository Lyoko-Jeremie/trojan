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

#ifndef TROJAN_IPRANGE_H
#define TROJAN_IPRANGE_H

#include <boost/asio/ip/address_v4_range.hpp>
#include <boost/asio/ip/address_v6_range.hpp>

extern bool parseRangeV4(const std::string &str, boost::asio::ip::address_v4_range &range);

extern bool parseRangeV6(const std::string &str, boost::asio::ip::address_v6_range &range);

#endif //TROJAN_IPRANGE_H
