@load base/protocols/dns

module DNSFilterCommon;

export {
	global dns_query_droplist: set[string] = set();
}

## The paraglob for droplist matching
global pg: opaque of paraglob;

## If the input file has been read at least once.
global initialized: bool = F;

event Input::end_of_data(name: string, source: string )
{
	if ( name != "dns_query_droplist")
		return;
	
	local res: vector of string;

	for ( query in dns_query_droplist )
		res[|res|] = query;

	pg = paraglob_init(res);
	initialized = T;
}

type Idx: record {
	query: string;
};

event zeek_init()
{
	Input::add_table([
		$name="dns_query_droplist",
		$source="dns_query_droplist.csv",
		$idx=Idx,
		$mode=Input::REREAD,
		$destination=dns_query_droplist
	]);
}

hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter) &priority=1
	{
	# We need a query to filter anything
	if ( ! rec?$query )
		return;

	# Netbios discovery
	if ( rec?$qtype && rec$qtype == 33 && rec$query == "*" )
		break;

	# If the input file has not been read yet, we can't do any droplist filtering.
	if ( ! initialized )
		return;

	local matches = paraglob_match(pg, rec$query);
	if (|matches| != 0)
		break;
	}
