import sys, os, pathlib, getopt,glob
import zlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# XOR Encryption 
def XOR_Encrypt(data):
    # Create 32-byte random key
    XOR_key = get_random_bytes(32)
    # XOR key code
    XOR_code = b"00"
    with open("file.key","wb") as XOR_keyfile:
            XOR_keyfile.write(XOR_key)
            XOR_keyfile.write(XOR_code)

    # Encrypted file
    binary_file=b""
    # XOR encryption
    data_encrypted=0
    while data_encrypted < len(data):
            binary_file += data[data_encrypted]^XOR_key[int(data_encrypted)%32]
            data_encrypted+=1
    return data_encrypted

# XOR Decryption
def XOR_Decrypt(data, XOR_keyfile):
    XOR_key=b""
    # Get XOR key from keyfile
    with open(XOR_keyfile,"wb") as XOR_keyfile:
            XOR_key=XOR_keyfile.read(32)

    # Create decrypted file
    XOR_decrypted_file=b""

    # XOR decryption
    data_decrypted=0
    while data_decrypted < len(data):
            XOR_decrypted_file+=data[data_decrypted]^XOR_key[int(data_decrypted)%32]
            data_decrypted+=1
    return data_decrypted

# AES Encryption
def AES_Encrypt(data):
    # Create 32-byte random key
    AES_key = get_random_bytes(32)
    # AES key code
    AES_code=b"01"

    with open("file.key", "wb") as AES_keyfile:
            AES_keyfile.write(AES_key)
            AES_keyfile.wrtie(AES_code)
    # Prepare for AES encryption
    AES_encrypt = AES.new(AES_key, AES.MODE_CBC)
    # Encrypted file
    encrypted_file = b""
    # Stored IV to decrypt
    encrypted_file += AES_encrypt.iv
        
    # AES encryption
    data_encrypted = 0
    while data_encrypted < len(data):
            if len(data) - data_encrypted > 65536:
                    encrypted_file += AES_encrypt.encrypt(
                            data[data_encrypted : data_encrypted + 65536])
            else:
                    encrypted_file += AES_encrypt.encrypt(data[data_encrypted:])
    data_encrypted += 65536
    return encrypted_file

# AES Decryption
def AES_Decrypt(data, AES_keyfile):
    AES_key = b""

    # Get AES key from file keyfile
    with open(AES_keyfile, "rb") as AES_keyfile:
            AES_key = AES_keyfile.read(32)

    # Create decrypted file
    AES_decrypted_file = b""
    # Intialization vector
    iv = data[:16]
    # Count decrypted bytes
    data_size_decrypted = 0

    # AES decryption
    AES_decrypt = AES.new(AES_key, AES.MODE_CBC, iv=iv)
    while data_size_decrypted < len(data):
            if len(data) - data_size_decrypted > 65536:
                    # Ignore first 16 bytes of IV 
                    AES_decrypted_file += AES_decrypt.decrypt(
                            data[data_size_decrypted + 16 : data_size_decrypted + 16 + 65536])
            else:
                    AES_decrypted_file += AES_decrypt.decrypt(data[data_size_decrypted + 16 :])

    data_size_decrypted += 65536
    return AES_decrypted_file

# Check which encryption algorithm was used to decrypt.
# When encrypting, there is a key code put in the last of the key file to distinguish which algorithm is used.
# XOR key code is 0x00;
# AES key code is 0x01.
# Read last byte to check which cipher was used.
def Decrypt(data,keyname):
    key=b""
    key_code=b""
    with open(keyname, "rb") as keyfile:
        key=keyfile.read()
        i=key.len()-1
        while (i > key.len()-3):
            key_code+=key[i]
            i=i-1
    if (key_code==b"00"):
        return XOR_Decrypt(data,keyname)
    if (key_code==b"01"): 
        return AES_Decrypt(data,keyname)

def Unpack(packed_file,keyname):
    # Decompress data
    # packed_file=zlib.decompress(packed_file)
    # Read packed file data
    readfile = open(packed_file, "rb")
    data = readfile.read()

    # Find posisions stored info of packed PE files
    startinfo = data.index(b"index=")
    endinfo = data.index(b"=end", startinfo) + 4

    # Decrypt data from bytes to string
    infoarray = (data[startinfo + 6 : endinfo - 4]).decode().split(":")

    # Decrypt packed PE file
    data_decrypted = Decrypt(data[endinfo:],keyname)
    endinfo = 0

    for i in range(int(len(infoarray) / 2)):
            # Print info of PE files chosen to pack
            print("File name: {name}     size: {size}".format(
                    name=infoarray[i * 2], size=infoarray[i * 2 + 1]))
            # Create new PE file
            file = open(infoarray[i * 2], "wb")
            # Write data to PE file
            file.write(data_decrypted[
                    endinfo : endinfo + int(infoarray[i * 2 + 1])])
            # Renew the starting position for the next packed PE file
            endinfo = endinfo + int(infoarray[i * 2 + 1])

def Pack(input_directory, output, algorithm):
    name = b"index="
    data = b""
        
    # Packer file's name
    exefile = sys.argv[0].split("\\")[-1]

    for exefile in glob.glob(input_directory + "/*.exe"):
            # Get size and location of files
            offset = os.path.getsize(exefile)
            # Print PE file's info
            print("File name : {name}     size: {size}".format(
                    name=exefile.split("\\")[-1], size=offset))
            # Get data in PE files
            readfile = open(exefile, "rb")
            # Store name and size of files
            name += (exefile.split("\\")[1] + ":" + str(offset) + ":").encode("utf-8")
            # Store files' data in data variable to encrypt
            data += readfile.read()

    thisfile = open(exefile, "rb")
    # New file for packed files
    newfile = open(output, "wb")
    # Compress file to decrease size
    # data=zlib.compress(data)

    # Choose an encryption algorithm want to use in packed PE file
    if(algorithm==1):
            newfile.write(thisfile.read() + name + b"=end" + XOR_Encrypt(data))
    elif(algorithm==2):
            newfile.write(thisfile.read() + name + b"=end" + AES_Encrypt(data))

def main(argv):
    # Choose directory including PE files want to pack;
    # Choose output file's name.
    input_dir=""
    output_file=""
    try:
            opts, args = getopt.getopt(argv, "i:o",["directory=","output_file="] )
    except getopt.GetoptError:
            print("Packer_a_c.exe -i <inputdirectory> -o <outputfile>")

    for opt, arg in opts:
            if opt== "-h":
                    print("Packer_a_c.exe -i <inputdirectory> -o <outputfile>")
                    sys.exit()
            elif opt in ("-i","--idirectory"):
                    input_dir=arg
            elif opt in ("-o","--ofile"):
                    output_file=arg
    if(input_dir=="" or output_file=="" ):
            print("Please select input directory name and output file")
    else:
            print("Input Directory is ", input_dir)
            print("Output File is", output_file)
            print("Please choose the algorithm to use : 1.XOR, 2.AES")
            x=input()
            while (x not in ["1","2"]):
                    print("Your choice is not supported. Please try again.")
                    x=input()
            Pack(input_dir, output_file, x)

if __name__ == "__main__":
    exefile = sys.argv[0].split("\\")[-1]
    print(os.path.getsize(exefile))

    file = open(exefile,'rb')
    data = file.read()

    try:
            startinfo = data.index(b"index=")
            endinfo = data.index(b"=end", startinfo) + 4
            originalsize = int((data[startinfo + 6 : endinfo - 4]).decode().split(":")[-1])
            # Check PE file is packed or not?
            # If it is, start unpacking.
            # If not, start packing PE file.
            if os.path.getsize(exefile) > originalsize:
                    Unpack(exefile,sys.argv[1])
    except:
            main(sys.argv[1:])