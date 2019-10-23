from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
from gmssl.func import xor, rotl, get_uint32_be, put_uint32_be, \
        bytes_to_list, list_to_bytes, padding, unpadding
import copy,os
from PIL import Image
key = b'3l5butlj26hvv313'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
ctr= 0

#分组密码CFB模式的加密算法
def crypt_cfb(input_data,crypt_mode):
    crypt_sm4=CryptSM4()
    crypt_sm4.mode=crypt_mode
    i = 0
    output_data = []
    tmp = [0]*16
    iv_tmp = bytes_to_list(iv)
    if crypt_sm4.mode == SM4_ENCRYPT:
        crypt_sm4.set_key(iv_tmp,SM4_ENCRYPT)
        input_data = padding(bytes_to_list(input_data))
        length = len(input_data)
        while length > 0:
            tmp[0:16] =crypt_sm4.one_round(crypt_sm4.sk,iv_tmp[0:16])
            output_data += xor(tmp[0:16],input_data[i:i+16])
            iv_tmp = copy.deepcopy(output_data[i:i+16])
            i += 16
            length -= 16
        return list_to_bytes(output_data)
    else:
        crypt_sm4.set_key(iv_tmp,SM4_ENCRYPT)
        length = len(input_data)
        while length > 0:
            tmp[0:16] =crypt_sm4.one_round(crypt_sm4.sk,iv_tmp[0:16])
            output_data += xor(tmp[0:16],input_data[i:i+16])
            iv_tmp = copy.deepcopy(input_data[i:i+16])
            i += 16
            length -= 16
        return unpadding(list_to_bytes(output_data))

#分组密码OFB模式的加密算法
def crypt_ofb(input_data,mode):
    crypt_sm4=CryptSM4()
    i = 0
    output_data = []
    tmp = [0]*16
    iv_tmp = bytes_to_list(iv)
    crypt_sm4.set_key(iv_tmp,SM4_ENCRYPT)
    if mode == SM4_ENCRYPT:
        input_data = padding(bytes_to_list(input_data))
    length = len(input_data)
    while length > 0:
        tmp[0:16] =crypt_sm4.one_round(crypt_sm4.sk,iv_tmp[0:16])
        output_data += xor(tmp[0:16],input_data[i:i+16])
        iv_tmp = copy.deepcopy(tmp[0:16])
        i += 16
        length -= 16
    if mode == SM4_DECRYPT:
        return unpadding(list_to_bytes(output_data))
    return list_to_bytes(output_data)

#分组密码CTR模式的加密算法
def crypt_ctr(input_data,mode):
    crypt_sm4=CryptSM4()
    i = 0
    output_data = []
    tmp = [0]*16
    ctr_tmp = ctr
    ctr_tmp_list=bytes_to_list(("%016x" % ctr_tmp).encode('ascii'))
    crypt_sm4.set_key(ctr_tmp_list,SM4_ENCRYPT)
    if mode == SM4_ENCRYPT:
        input_data = padding(bytes_to_list(input_data))
    length = len(input_data)
    while length > 0:
        tmp[0:16] =crypt_sm4.one_round(crypt_sm4.sk,ctr_tmp_list[0:16])
        output_data += xor(tmp[0:16],input_data[i:i+16])
        ctr_tmp+=1
        ctr_tmp_list=bytes_to_list(("%016x" % ctr_tmp).encode('ascii'))
        i += 16
        length -= 16
    if mode == SM4_DECRYPT:
        return unpadding(list_to_bytes(output_data))
    return list_to_bytes(output_data)

#读取图片文件的像素点数据
def read_file(file_path):
    img_src = Image.open(file_path)
    str_strlist = img_src.load()
    pixel_data_list=[]
    for i in range(0,img_src.width):
        for j in range(0,img_src.height):
            pixel=list(str_strlist[i,j])
            pixel_data_list += pixel
    pixel_data=list_to_bytes(pixel_data_list)
    img_src.close()
    return pixel_data

#将像素点数据存储在图片中
def save_file(file_path,file_path_save,pixel_data):
    img_src = Image.open(file_path)
    img_save=img_src.copy()
    pixel_data_list=bytes_to_list(pixel_data)
    for i in range(0,img_save.width):
        for j in range(0,img_save.height):
            pixel=list(img_save.getpixel((i,j)))
            for k in range(0,4):
                pixel[k]=int(pixel_data_list[(i*img_save.height+j)*4+k])
            img_save.putpixel((i,j),tuple(pixel))
    img_save.save(file_path_save)
    img_save.close()


#验证ECB模式，加密一个图片像素点，然后解密，将加密后的像素点和解密后的像素点数据存储在图片中
def sm4_ecb(value):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_ecb(value)
    crypt_sm4.set_key(key, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
    save_file("logo.png",".\\result\\logo_ecb_en.png",encrypt_value)
    save_file("logo.png",".\\result\\logo_ecb_de.png",decrypt_value)
    if value==decrypt_value:
        print("ECB is ok!")

#验证CBC模式，加密一个图片像素点，然后解密，将加密后的像素点和解密后的像素点数据存储在图片中
def sm4_cbc(value):
    crypt_sm4 = CryptSM4()
    crypt_sm4.set_key(key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_cbc(iv , value)
    crypt_sm4.set_key(key, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_cbc(iv,encrypt_value)
    save_file("logo.png",".\\result\\logo_cbc_en.png",encrypt_value)
    save_file("logo.png",".\\result\\logo_cbc_de.png",decrypt_value)
    if value==decrypt_value:
        print("CBC is ok!")
#验证CFB模式，加密一个图片像素点，然后解密，将加密后的像素点和解密后的像素点数据存储在图片中
def sm4_cfb(value):
    encrypt_value=crypt_cfb(value,SM4_ENCRYPT)
    decrypt_value=crypt_cfb(encrypt_value,SM4_DECRYPT)
    save_file("logo.png",".\\result\\logo_cfb_en.png",encrypt_value)
    save_file("logo.png",".\\result\\logo_cfb_de.png",decrypt_value)
    if value==decrypt_value:
        print("CFB is ok!")
#验证OFB模式，加密一个图片像素点，然后解密，将加密后的像素点和解密后的像素点数据存储在图片中
def sm4_ofb(value):
    encrypt_value=crypt_ofb(value,SM4_ENCRYPT)
    decrypt_value=crypt_ofb(encrypt_value,SM4_DECRYPT)
    save_file("logo.png",".\\result\\logo_ofb_en.png",encrypt_value)
    save_file("logo.png",".\\result\\logo_ofb_de.png",decrypt_value)
    if value == decrypt_value:
        print("OFB is ok!")

#验证CTR模式，加密一个图片像素点，然后解密，将加密后的像素点和解密后的像素点数据存储在图片中
def sm4_ctr(value):
    encrypt_value=crypt_ctr(value,SM4_ENCRYPT)
    decrypt_value=crypt_ctr(encrypt_value,SM4_DECRYPT)
    save_file("logo.png",".\\result\\logo_ctr_en.png",encrypt_value)
    save_file("logo.png",".\\result\\logo_ctr_de.png",decrypt_value)
    if value==decrypt_value:
        print("CTR is ok!")
def main():
    value=read_file("logo.png")
    if 1-os.path.exists(".\\result"):
        os.mkdir(".\\result")
    sm4_ecb(value)
    sm4_cbc(value)
    sm4_cfb(value)
    sm4_ofb(value)
    sm4_ctr(value)
if __name__ == "__main__":
    main()



    