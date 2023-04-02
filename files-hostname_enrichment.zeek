redef record Files::Info += {

          orig_hostname: set[string] &log &optional &default=string_set();
          resp_hostname: set[string] &log &optional &default=string_set();

};


event file_sniff(f: fa_file, meta: fa_metadata){

        if (f?$conns)
         {
             for (cid,c in f$conns)
             {


                  if ( c$id?$orig_hostname){

                          add f$info$orig_hostname[c$id$orig_hostname];
                  }
                  if ( c$id?$resp_hostname){

                          add f$info$resp_hostname[c$id$resp_hostname];
                  }
             }


         }

}
