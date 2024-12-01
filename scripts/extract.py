#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

if __name__ in '__main__':
    parser = argparse.ArgumentParser( description = 'Extract a position independent shellcode from an executable.' )
    parser.add_argument( 'pepath', help = 'Path to the portable executable containing the shellcode.', type = str )
    parser.add_argument( 'scpath', help = 'Path to write the extracted shellcode.', type = argparse.FileType( 'wb+' ) )
    args = parser.parse_args()

    pe = pefile.PE( args.pepath );

    if len( pe.sections ) != 1:
        raise Exception( 'There should only be 1 section, there is currently {}'.format( len( pe.sections ) ) );

    code = pe.sections[ 0 ].get_data()

    offs = code.find( b'GAROU-END' );

    if offs is None or offs == 0:
        raise Exception( 'The end of code marker is missing from the executable.' );

    code = code[ : offs ]

    args.scpath.write( code );