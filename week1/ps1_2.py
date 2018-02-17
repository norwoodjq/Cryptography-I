# -*- coding: utf-8 -*-
"""
Created on Mon Jul 17 13:28:11 2017

@author: John
"""


c1 = '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e'
c2 = '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f'
c3 = '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb'
c4 = '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa'
c5 = '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070'
c6 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4'
c7 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce'
c8 = '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3'
c9 = '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027'
c10 = '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83'
target = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

ciphers = [target, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10]

c1MSB20 = 0x315c4eeaa8b5f8aaf9174145bf43e1784b8fa00d
c2MSB20 = 0x234c02ecbbfbafa3ed18510abd11fa724fcda201
c3MSB20 = 0x32510ba9a7b2bba9b8005d43a304b5714cc0bb0c

c1LSB20 = 0x65286764703de0f3d524400a19b159610b11ef3e
c2LSB20 = 0xcb24cc5b028aa76eb7b4ab24171ab3cdadb8356f
c3LSB20 = 0xe503c66e935de81230b59b7afb5f41afa8d661cb
#lenc1 = len(hex(c1))
#lenc2 = len(hex(c2))
#lenc3 = len(hex(c3))
#lenc4 = len(hex(c4))
#lenc5 = len(hex(c5))
#lenc6 = len(hex(c6))
#lenc7 = len(hex(c7))
#lenc8 = len(hex(c8))
#lenc9 = len(hex(c9))
#lenc10 = len(hex(c10))
#lentarget = len(hex(target))

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        c = [(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)]
        print(c)     
    else:
        c = [(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])]
        print(c)
 #   return "".join([bytes([e]).hex() for e in c])
    return c
       
def makenewstr(msg):
    newstring=''
    for index in range(len(msg)):
        newstring+=msg[index]
    return newstring
    
def xorb(a,b):
    # xor two unequal hex strings, truncating the longer string
    # i.e. a = '5c5d' b = '5c5d' returns result = '0000'
    #      a = '5c5d' b = '5c' returns result = '00'
    #      a = '5c'   b = '5c5d' returns result = '00'
    rawa = bytes.fromhex(a)
    rawb = bytes.fromhex(b)
    rawresult = bytes(x^y for x,y in zip(rawa,rawb))
    result = rawresult.hex()
    return result
    
def stringToHex(a):
    b=a.encode()
    return b.hex()
    
def xorWithSpace(a):
    # takes a hex string of the form '315c43eaa8b5'
    # returns the xor of each byte and the space character, ' '.
    # return value, result, is a hex string
    # i.e. input = '315c42eaa8b5' returns result = '117c62ca8895'
    # ord(' ') = 32  hex(32) = 0x20
    # 0x31 = 49  49^32 = 17, hex(17) = 0x11
    # 0x5c = 92  92^32 = 124, hex(124) = 0x7c
    # 0x42 = 66  66^32 = 98, hex(98) = 0x62
    # 0xea = 234 234^32=202, hex(202) = 0xca
    # 0xa8 = 168 168^32 =136, hex(136) = 0x88
    # 0xb5 = 181 149^32 = 149, hex(149) = 0x95
    #
    rawa=bytes.fromhex(a)
 #   print("raw_a", rawa)
    space = ord(' ') # xorable ascii code of ' ' is 32
#    spacehex = ' '.encode().hex() # hexstring form of space: '20'
#    print("space", space)
    result=''
    for byte in rawa:
#        print("byte: ", byte)
        bytexor = hex(byte^space)[2:]
#        print("bytexor: ", bytexor)
        result+=bytexor
    return result
    
def xorWith_the_(a, crib=' the '):
    # takes the input c1^c2 and the 5 char string ' the '
    rawa = bytes.fromhex(a)
    index = 0
    k = []
    for byte in rawa:
        for jndex in range(len(crib)):
            k[index+jndex]=rawa[index+jndex]
            text= ord(crib[jndex])^k[index+jndex]
            print('text:', text, ' key:', k[index+jndex])
        print('index:', index)
        index+=1
        
charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTVWXYZ!"#$%&\'(*+,-./0123456789:;<=>?'      
letterset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTVWXYZ'        
 
def hexToAscii(a):
# converts a hex string into a series of ascii codes
# then converts the codes letter by letter and assembles a text string
# returns the decoded text string
# i.e. a = '6465636f64652074686973' returns 'decode this' 
    result = ''
    for index in range(1,len(a)+1, 2):    
        try:
            thisbyte = bytes.fromhex(a[index-1:index+1])
            if thisbyte == '00':
                result+='0'
            else: 
                letter = thisbyte.decode()
            if letter in charset:
                result+=letter
            else: 
  #              print('not letter or null')
                result+='*'
        except:
  #          print('exception')
            result+='*'
    return result
    
def findSpaces(tc, c1, c2):
    table = []
    result=''
    txorc1 = xorb(tc, c1)
#    print('txorc1: ', txorc1)
    txorc1_t = hexToAscii(txorc1)
    txorc2 = xorb(tc, c2)
#    print('txorc2: ', txorc2)
    txorc2_t = hexToAscii(txorc2)  
 #   print('txorc1_t: ', txorc1_t)
 #   print('txorc2_t: ', txorc2_t)
#    print('target: ', hexToAscii(t))
#    print(len(hexToAscii(t)))
#    print(minimum)
    minimum = min([len(txorc1_t), len(txorc2_t), len(hexToAscii(tc))])
#    print(minimum, len(hexToAscii(tc)))
    for index in range(minimum):
        if txorc1_t[index] in letterset and txorc2_t[index] in letterset:
 #           print('keys: '+ tc[2*index:2*index+1] +' '+ c1[2*index:2*index+1]+ ' ' + c2[2*index:2*index+1] + '  values: '+ txorc1_t[index]+ ' '+ txorc2_t[index] )
            table.append((tc[2*index:2*index+2], c1[2*index:2*index+2], c2[2*index:2*index+2], txorc1_t[index], txorc2_t[index]))
            result+=' '
        else:
            result+='*'
    table.append(result)
    return table
    
def readable(c1, c2):
    c1_t = hexToAscii(c1)
    print(c1_t)
    c2_t = hexToAscii(c2)
    print(c2_t)
    c12_t=hexToAscii(xorb(c1,c2))
    print(c12_t)
    
def findLetters(t, c1, c2, m):
    m=findSpaces(t, c1, c2, m)
    for index in range(len(m)):
        if m[index]==' ':
            pass
        
def getByte(c1, index):
    byteHex = c1[2*index:2*index+2]
#    print(byteHex)
    return ord(bytes.fromhex(byteHex))
    
def ordList(c):
    results=[]
    blist = bytes.fromhex(c)
    for byte in blist:
        results.append(byte)
    return results
        
def hasCode(a, c):
    # a is  ascii code
    # c is ciphertext as a hex string
    results=[]
    cList = ordList(c)
    for index in range(len(cList)):
        if a == cList[index]:
            results.append(index)
    return results
    
key = '814f76125b5e492bb5554a114aaa4e30558e128f462f74457547c72a7857475e4d5cc9eb9b0edcd5b7535c13e7413867a16c7b004dff94e6f57067efccbce884d71eecfc6e818c2916576012633f18dc4c695f584d04a38e745bbf90463ef5075f9bdf87b80977b2a9998d424dc671f55b0aa5a8fa4552d6a32ccd022b54b5e52ba812d70c4a321a0d1a5cccdb25ba2868b4d15904278b379554732bbdb7b4dc20978915dd1550982e61a6e6cae0d6e74d1371814538277d2a038611b8a3d9ba7ba4eeb9b9db8ee1586d113b3286f17f6d1264af0fb5989a29c049a9e304ff1e45a91a0f903dfc3f0acb05bc056512deaa8f0ad249d490ea26ee4ef6b806d70af11f8cf58b43c61175c8b68187d6ad7de5bc37e43388550cbaf212d3d87e2752142c288a2b04088068233b817bcbec5aae33cc3e4f030009a617d09dd1320901ec30a21c916ed28d30e656a4aee598c31a6a1651b2e6636185bc31c46bf6f2b9fbb684fe2091c34dd178f8b59673439a41c3d94671d9921e3f5cfc774d3acdf1fdbfb7bf411f31eaf357ef1558fa8691ccced84c67d5cfcf1d28f12bb7b16512911b94ed559f73a275def61d7ac7c2898320ea902b8b1f76279c4a9cf31d99d25a5487132013e9e57ae6a18397ba6af7c12af76a32082a317fe283b54601af508033bc342d678f610e992a7fbaed890809628b56561b687e302f6b0a060b36fd'
    
def encrypt(key, msg):
    enc_msg = msg.encode().hex()
    c = xorb(key, enc_msg)
    return c
    
tm1 = 'this is a test'
tm2 = 'over the hill'
tm3 = 'u v w x y z'
tm4 = 'hello world'
tm5 = 'quadratic equation'
tm6 = 'zebras have stripes'
tm7 = 'a rat in the kitchen'
tm8 = 'on top of the world'
tm9 = 'a b c d e f g h i j'
tm10 = ' k l m n o p q r s t'
ttm = 'decode me'
        
tc1 = encrypt(key, tm1)
tc2 = encrypt(key, tm2)
tc3 = encrypt(key, tm3)
tc4 = encrypt(key, tm4)
tc5 = encrypt(key, tm5)
tc6 = encrypt(key, tm6)
tc7 = encrypt(key, tm7)
tc8 = encrypt(key, tm8)
tc9 = encrypt(key, tm9)
tc10 = encrypt(key,tm10)
ttc = encrypt(key, ttm)

test_c = [ttc, tc1, tc2, tc3, tc4, tc5, tc6, tc7, tc8, tc9, tc10]

def runTest(ciphers): 
#    print()
    results=[]
    tc = ciphers[0]
    minlen = int(len(ciphers[0])/2)
    for c in ciphers:
        thislen = int(len(c)/2)
        if thislen<minlen:
            minlen=thislen
    test_c = ciphers[1:]
    m_list = []
    for c1 in test_c:
        for c2 in test_c:
            if c1!=c2:
                thisiter = findSpaces(tc, c1, c2)
  #              print(thisiter)
  #              print(len(thisiter))
                m_list.append(thisiter)
 #   print(len(m_list))  
 
    thresh = 0.3*(len(m_list))
    counts = [0]*len(m_list[0][-1])
    for i in range(len(m_list)):
#        print('m_list[i][-1]', m_list[i][-1])
        for j in range(len(m_list[i][-1])):
            try: 
                if m_list[i][-1][j]==' ':   
 #                   print('space ' , len(m_list), i, len(m_list[0]), j, counts)
                    counts[j]+=1
                else: 
 #                   print('not a space ' , len(m_list), i, len(m_list[0]), j, counts)
                    pass
            except:
 #               print(len(m_list), i, len(m_list[0]), j, counts)
                 pass
#                print('exception255: ', len(m_list), i, len(m_list[0]), j, counts)
    for index in range(minlen):
        if counts[index]>thresh:
            for j in range(len(m_list)):
                try:
                    if m_list[j][-1][index]==' ':
  #                      print('m_list: ', m_list[j], '   index: ', index )
  # m_list format
  # ((tc[2*index:2*index+1], c1[2*index:2*index+1], c2[2*index:2*index+1], txorc1_t[index], txorc2_t[index]))
                        results.append((m_list[j], index))
                except:
 #                   pass
                    print('exception267. index:', index, ' j:', j)
                    print('m_list[j][-1][index]')
                    print('len(counts):', len(counts))
                    print('m_list[j][-1]:', m_list[j][-1])
                    return []
    return results
        
def keyTables(ciphers):
    target = ciphers[0]
    test_c = ciphers[1:]
    keytable =[]
    for c1 in range(len(test_c)):
        for c2 in range(len(test_c)):
            if c1!=c2:
                xorc1 = xorb(target, test_c[c1])
                xorc2 = xorb(target, test_c[c2])
                keytable.append((xorc1, xorc2))
    return keytable

def findKeys(ciphers):
    keys=[]
    results = runTest(ciphers)
    keytable = keyTables(ciphers)
    target = ciphers[0]
    for elem in results:
        key = target[2*elem[1]:2*elem[1]+1]
        index = elem[0]
        pvalue1 = keytable[index][0]
        pvalue2 = keytable[index][1]
        value1 = (pvalue1[2*elem[1]:2*elem[1]+1])
        print(value1)
        value2 = (pvalue2[2*elem[1]:2*elem[1]+1])
        print(value2)
        keys.append((key, value1, value2))
    return keys
        
def rotCiphers(ciphers):
    new_ciphers = ciphers[:]
    p = new_ciphers.pop(0)
    new_ciphers.append(p)
    return new_ciphers

def buildDict(results):
    # discard bad values for ' ' decode
    dict ={}
    space_codes = {}
    for line in results:
        # a line might look like this: ([('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H'), '**** * **'], 6)
        # len(line)=2, so drop line[-1] and focus on line[0], subline = line[0]
        # subline looks like this: [('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H'), '**** * **']
        # drop subline[-1], so codes = subline[:-1]
        # so codes looks like this: [('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H')]
        # then iterate through codes, looking at codes[i][0]
        # build a dict of the different codes interpreted as spaces, in the example '3f' and '69'
        # counting the instances of each, then pick the most frequent as the correct interpretation
        #
        # next go back though the lines and grab only the codes with the correct interpretation of spaces
        # build a dictionary, dict, with the other code/letter pairs
        # in this example: ('69', '3a', '21', 'S', 'H')
        # '69' is the key, ' ' is value. so add these key:values to dict: '3a':'S' and '21'='H'
        # after iterating through all valid codes in all lines, return the dictionary
        subline = line[0]
        codes = subline[:-1]
 #       print(codes)
        for c in codes:
            if not c[0] in space_codes:
                space_codes[c[0]] = 1
            else:
                space_codes[c[0]] += 1
    #  at this point, we should be able to pick out the correct code for ' '

    max = 0
    for key in space_codes:
        if space_codes[key]>max:
            space = key
            max = space_codes[key]
    print('code for \' \': ', space)
    print('space codes: ', space_codes)
    dict[space]=' '
    for line in results:
        codes = line[0][:-1]
        for c in codes:
            if c[0]==space:
                dict[c[1]]=c[3]
                dict[c[2]]=c[4]
    return dict

def buildBigDict(ciphers):
    dict = {}
    cipher_copy = ciphers[:]
    for i in range(len(cipher_copy)):
        results = runTest(cipher_copy)
        subdict = buildDict(results)
        cipher_copy = rotCiphers(cipher_copy)
        for key in subdict:
            dict[key]=subdict[key]
    return dict

def buildBigDict2(ciphers):
    dict = {}
    cipher_copy = ciphers[:]
    results = runTest(cipher_copy)
    dict = buildDict(results)
    return dict

def getSpaceIndex(target, code):
    for i in range(0, len(target), 2):
        check = target[i:i+2]
 #       print(code, ' ' , check)
        if code==check:
 #           print('found match')
            return int(i/2)
    print('code not found. target: ', target, ' code: ', code)

def returnKey(ciphers):
    cipher_copy = ciphers[:]
    target = cipher_copy[0]
    results = runTest(cipher_copy)
#    print(results)
    # discard bad values for ' ' decode

    space_codes = {}
#    K = ['*']*len(results[0][0][-1])
#    print('K= ', K)
    for line in results:
        # a line might look like this: ([('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H'), '**** * **'], 6)
        # len(line)=2, so drop line[-1] and focus on line[0], subline = line[0]
        # subline looks like this: [('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H'), '**** * **']
        # drop subline[-1], so codes = subline[:-1]
        # so codes looks like this: [('3f', '7b', '7b', 'D', 'D'), ('69', '3a', '21', 'S', 'H')]
        # then iterate through codes, looking at codes[i][0]
        # build a dict of the different codes interpreted as spaces, in the example '3f' and '69'
        # counting the instances of each, then pick the most frequent as the correct interpretation
        #
        # next go back though the lines and grab only the codes with the correct interpretation of spaces
        # build a dictionary, dict, with the other code/letter pairs
        # in this example: ('69', '3a', '21', 'S', 'H')
        # '69' is the key, ' ' is value. so add these key:values to dict: '3a':'S' and '21'='H'
        # after iterating through all valid codes in all lines, return the dictionary
        subline = line[0]
        codes = subline[:-1]
 #       print(codes)
        for c in codes:
            if not c[0] in space_codes:
                space_codes[c[0]] = 1
            else:
                space_codes[c[0]] += 1
    #  at this point, we should be able to pick out the correct code for ' '

    max = 0
    space = None
    for key in space_codes:
        if space_codes[key]>max:
            space = key
            max = space_codes[key]
#    print('code for \' \': ', space)
#    print('space codes: ', space_codes)
#    print('target: ', target, '   code: ', space)
    if space!=None:
        try:
            space_index=getSpaceIndex(target,space)
#            print('space index: ', space_index, '  space: ', space)
            return (space_index, space)
        except:
            print('exception427')
    return ('null', 'null')

#    K[space_index] = space
#    print('K = ', K)
    

def findMultKey(ciphers):
    K =[]
    cipher_copy = ciphers[:]
    for i in range(len(cipher_copy)):
        K.append(returnKey(cipher_copy))
        cipher_copy = rotCiphers(cipher_copy)
    return K

def assembleKey(ciphers):
    numKeys = int(len(ciphers[0])/2)
    K = ['*']*numKeys
#    print('K: ', K)
    KeyTuple = findMultKey(ciphers)
    for pair in KeyTuple:
        if pair[0]!='null':
            K[pair[0]]=pair[1]
    return K

def purgeResults(results):
    dict = {}
    ilist = []
    try: 
        keylen = len(results[0][0][-1])
    except:
        print(results)
        return []
    for line in results:
        kl = len(line[0][-1])
        if kl<keylen:
            keylen = kl
#    print('keylen: ', keylen)
    for line in results:
        for i in range(keylen):
            try:
                if line[0][-1][i]==' ':
                    if not i in dict:
                        dict[i]=1
                    else:
                        dict[i]+=1
            except:
                print('exception466. i:', i, 'keylen:', keylen)
                print(line)
                break
    for key in dict:
        if dict[key]>len(results)/10:
            ilist.append(key)     
    return ilist

def getSpaceIndexList(phrase):
    ilist = []
    for i in range(len(phrase)):
        if phrase[i]==' ':
            ilist.append(i)
    return ilist


def getPurgedResults(ciphers):
    results = runTest(ciphers)
    try:
        kl = len(results[0][0][-1])
        K = ['*']*kl
    except:
 #       print(len(results))
        return []
#    print(K)
    ilist = purgeResults(results)
    for i in range(len(ilist)):
        for line in results:
            phrase = line[0][-1]
            if phrase[ilist[i]]==' ':
                space_loc= []
                for j in range(ilist[i]):
                    if phrase[j]==' ':
                        space_loc.append(j)
                try:
                    K[ilist[i]]=line[0][len(space_loc)][0]
                except:
                    if i == 0:
                        print(line)
                    print('i:', i, ' ilist:', ilist)
                    print('k[ilist[i]]:', K[ilist[i]])
                    print('line[0]:', line[0])
                    print('space_loc')
  #                  print('ilist[i]:', ilist[i], ' line[0][i][0]:', line[0][i][0], ' i:', i)
  #              print(line[i][0])
                break
#    print('done')
    return K

def getMoreK(ciphers):
    ciphers_copy = ciphers[:]
    finalK = getPurgedResults(ciphers_copy)
    for i in range(len(ciphers_copy)):
        ciphers_copy = rotCiphers(ciphers_copy)
        K = getPurgedResults(ciphers_copy)
        if len(K)<len(finalK):
            keylen=len(K)
        else:
            keylen=len(finalK)
        for j in range(keylen):
            if K[j]!='*':
                try:
                    if K[j]!=finalK[j]:
                        print('duplicate:', K[j])
                    else:
                            finalK[j]=K[j]
                except:
                    print('exception531. K: ', K)
                    print('i:', j)
                    print('finalK:', finalK)
    return K

def decodeMsg(K, c):
    decoded_message = []
    for i in range(0, len(c), 2):
        if K[i]!='*':
            encbyte = c[i:i+2]
            print(encbyte)
            letter = xorb(K[i],encbyte)
            print(letter)
            decoded_message+=letter
        else: 
            decoded_message+='*'
    return decoded_message

def listToString(list):
    string = ''
    for k in list:
        string+=k
    return string

def decodeK(Kstring):
    K=[]
    for i in range(len(Kstring)):
        if i%2==1:
            K.append(Kstring[i-1:i+1])      
    string = ''
#    print(K)
    M = []
    for k in K:
        letter = chr(ord(bytes.fromhex(k)))
        string+=letter
        M.append(letter)
    print(string)    
    return (K,M)

def combineK(K1, K2):
    if len(K1)<len(K2):
        minlen = len(K1)
        shorter = K1
        longer = K2
    else: 
        minlen = len(K2)
        shorter =  K2
        longer = K1
    comboK=longer[:]
    for i in range(minlen):
        if shorter[i]!='*':
            if shorter[i]==longer[i]:
                print('dup:', shorter[i])
            elif longer[i]!='*':
                print('conflict: K1[i]:', K1[i], ' K2[i]:', K2[i])
                comboK[i]='*'
            else:
                print('yay!')
                comboK[i]=shorter[i]
    return comboK

def combineAllK(ciphers):
    c_copy = ciphers[:]
    Klist = []
    Klist.append(getPurgedResults(c_copy))
    for i in range(len(ciphers)):
        c_copy = rotCiphers(c_copy)
        Klist.append(getPurgedResults(c_copy))
    comboK = Klist[0]
    for k in range(len(Klist)-1):
        comboK = combineK(comboK,Klist[k+1])
    print(listToString(comboK))
    print()
    for i in range(len(comboK)):
        try:
            if comboK[i]=='*':
                comboK[i]='00'
        except:
            print('exeption612. [i]:', i)
            ks = listToString(comboK)
            print('comboK:', ks)
 #   dec_string = decodeK(comboK)
 #   print(dec_string)
    print('lenK:', len(comboK), ' len(target):', len(ciphers[0]))
    Kstring = listToString(comboK)
    print(Kstring)
    print()
    print(ciphers[0])
    decode = xorb(Kstring, target)
    return decode

tcM = ['d', 'e', 'c', 'o', 'd', 'e', ' ', 'm', 'e']
tcK = ['81', '4f', '26', '12', '5b', '5e', '49', '2b', 'b5']

def main():
    decode = combineAllK(ciphers)
    answer = hexToAscii(decode)
    print(answer)



    
                
        

        