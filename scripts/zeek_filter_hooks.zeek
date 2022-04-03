
# Conn log
hook Conn::log_policy(rec: Conn::Info, id: Log::ID, filter: Log::Filter)
    {
    # Exclude DNS Service logs from Conn
    if ((rec?$service) && ((rec$service == "dns")))
        break;
    }


# Files log
hook Files::log_policy(rec: Files::Info, id: Log::ID, filter: Log::Filter)
    {
    # Exclude cert related entries from the Files log
    if ((rec?$mime_type) && ((rec$mime_type == "application/pkix-cert") || 
                             (rec$mime_type == "application/x-x509-ca-cert") || 
                             (rec$mime_type == "application/x-x509-user-cert") ||
                             (rec$mime_type == "application/ocsp-response") ))
        break;
    }

# DNS log
hook DNS::log_policy(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
    {
    # Exclude NBSTAT wildcard queries
    if ((rec?$qtype_name) && (rec$qtype_name == "NBSTAT") && (rec?$query) && (rec$query == "*"))
        break;
        
    # Exclude no query no answers
    if (! (rec?$query) && ! (rec?$answers))
        break;
    }
