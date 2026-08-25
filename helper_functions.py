def print_binary(hex_val):
    out_str = ""
    check = 128
    while check >= 1:
        if (hex_val & int(check)): 
            out_str += "1"
        else:
            out_str += "0"
        check = check / 2
    print(out_str)