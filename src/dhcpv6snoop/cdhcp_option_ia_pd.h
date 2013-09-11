/*
 * cdhcp_option_ia_pd.h
 *
 *  Created on: 11.09.2013
 *      Author: andreas
 */

#ifndef CDHCP_OPTION_IA_PD_H_
#define CDHCP_OPTION_IA_PD_H_

#include <map>

/*
 * RFC 3633: Identity Association for Prefix Delegation
 */

#include "cdhcp_option.h"
#include "cdhcp_option_ia_pd_option_prefix.h"

namespace dhcpv6snoop
{

class cdhcp_option_ia_pd :
		public cdhcp_option
{
public:

	enum cdhcp_option_ia_pd_type {
		DHCP_OPTION_IA_PD = 25,
	};

	struct dhcp_option_ia_pd_hdr_t {
		struct dhcp_option_hdr_t header;
		uint32_t 	iaid;
		uint32_t 	t1;
		uint32_t 	t2;
		uint8_t 	data[0];
	};

private:

	struct dhcp_option_ia_pd_hdr_t *hdr;
	std::map<uint16_t, cdhcp_option*> options;

public:

	cdhcp_option_ia_pd();

	cdhcp_option_ia_pd(uint8_t *buf, size_t buflen);

	virtual ~cdhcp_option_ia_pd();

	cdhcp_option_ia_pd(const cdhcp_option_ia_pd& opt);

	cdhcp_option_ia_pd& operator= (const cdhcp_option_ia_pd& opt);

public:

	virtual void
	validate();

	virtual uint8_t*
	resize(size_t len);

	virtual void
	pack(uint8_t *buf, size_t buflen);

	virtual void
	unpack(uint8_t *buf, size_t buflen);

	virtual size_t
	length();

public:

	uint32_t
	get_iaid() const;

	void
	set_iaid(uint32_t iaid);

	uint32_t
	get_t1() const;

	void
	set_t1(uint32_t t1);

	uint32_t
	get_t2() const;

	void
	set_t2(uint32_t t2);

	cdhcp_option&
	get_option(uint16_t code);

private:

	size_t
	options_length();

	void
	pack_options(uint8_t *buf, size_t buflen);

	void
	unpack_options(uint8_t *buf, size_t buflen);

	void
	purge_options();

public:

	friend std::ostream&
	operator<< (std::ostream& os, const cdhcp_option_ia_pd& opt) {
		os << dynamic_cast<const cdhcp_option&>( opt );
		os << "<dhcp-option-ia-pd: ";
			os << "iaid: " << (int)opt.get_iaid() << " ";
			os << "t1: " << (unsigned int)opt.get_t1() << " ";
			os << "t2: " << (unsigned int)opt.get_t2() << " ";
			for (std::map<uint16_t, cdhcp_option*>::const_iterator
						it = opt.options.begin(); it != opt.options.end(); ++it) {
					os << *(it->second) << " ";
				}
		os << ">";
		return os;
	};
};


}; // end of namespace

#endif /* CDHCP_OPTION_IA_PD_H_ */
