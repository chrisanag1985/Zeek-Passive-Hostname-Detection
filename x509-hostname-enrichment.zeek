redef record X509::Info += {

       orig_hostname: set[string] &log &optional &default=string_set();
       resp_hostname: set[string] &log &optional &default=string_set();
};


event x509_certificate(f: fa_file, cert_ref: opaque of x509,cert: X509::Certificate)
{
             for (cid,c in f$conns)
             {


                  if ( c$id?$orig_hostname){

                          add f$info$x509$orig_hostname[c$id$orig_hostname];
                  }
                  if ( c$id?$resp_hostname){

                          add f$info$x509$resp_hostname[c$id$resp_hostname];
                  }

             }


}
