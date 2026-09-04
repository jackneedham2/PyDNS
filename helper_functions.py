def print_binary(hex_val):
    out_str = ""
    check = 256
    while check >= 1:
        if (hex_val & int(check)): 
            out_str += "1"
        else:
            out_str += "0"
        check = check / 2
    print(out_str)

def nbo_to_int(b):
    return (b[0] << 8)+b[1]