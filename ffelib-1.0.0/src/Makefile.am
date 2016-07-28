AM_LDFLAGS = -lgmp -ltepla -lcrypto -lintl -lglib-2.0
AM_CFLAGS = -I/usr/local/include -I/usr/include -I../ -I/opt/local/include/glib-2.0 -I/opt/local/lib/glib-2.0/include -L/opt/local/lib -L/usr/local/lib

bin_PROGRAMS = tfel-setup tfel-keygen tfel-enc tfel-dec

tfel_setup_SOURCES = setup.c common.h base64.c tfel_export_file.c tfel_matrix.c tfel_dpvs.c util.c sha1.c


tfel_keygen_SOURCES = KeyGen.c tfel_import_file.c base64.c csv_converter.c tfel_attribute.c policy.tab.c tfel_matrix.c tfel_spanprogram.c util.c sha1.c tfel_access_structure.c tfel_dpvs.c tfel_export_file.c


tfel_enc_SOURCES = Enc.c tfel_spanprogram.c tfel_import_file.c csv_converter.c base64.c tfel_matrix.c tfel_attribute.c util.c sha1.c policy.tab.c tfel_access_structure.c tfel_export_file.c tfel_dpvs.c

tfel_dec_SOURCES = Dec.c tfel_spanprogram.c tfel_import_file.c csv_converter.c base64.c tfel_matrix.c tfel_attribute.c util.c sha1.c policy.tab.c tfel_access_structure.c tfel_export_file.c tfel_dpvs.c
