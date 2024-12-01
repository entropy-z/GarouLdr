#!/usr/bin/env python3

import argparse
import pefile

def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

def extract_text_section(pe_path):
    pe = pefile.PE(pe_path)
    for section in pe.sections:
        if section.Name.replace(b'\x00', b'').decode('utf-8') == ".text":
            print(f"[*] Found .text section [size: {len(section.get_data())} bytes]")
            return section.get_data()
    raise ValueError("No .text section found in the PE file.")

def insert_data_into_pe(bin_data, pe_path, output_path):
    pe_data  = read_file(pe_path)
    new_data = bin_data + pe_data
    write_file(output_path, new_data)

def main():
    parser = argparse.ArgumentParser(description='Insert the .text section of a source PE file into the beginning of a destination PE file.')
    parser.add_argument('-r', '--reflectiveldr', required=True, help='Path to the source PE file')
    parser.add_argument('-d', '--dll', required=True, help='Path to the destination PE file')
    parser.add_argument('-o', '--output', required=True, help='Path to the output PE file')
    args = parser.parse_args()

    try:
        data = read_file( args.reflectiveldr )
        insert_data_into_pe(data, args.dll, args.output)
        print(f"[*] Successfully inserted Garou UDRL into {args.output}")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
