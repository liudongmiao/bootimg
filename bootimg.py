#!/usr/bin/env python
#fileencoding: utf-8
#Author: Liu DongMiao <liudongmiao@gmail.com>
#Created  : Sun 17 Oct 2010 11:19:58 AM CST
#Modified : Fri 04 Nov 2016 10:12:42 PM CST

import os
import sys
import mmap
import json
import struct
from stat import *
from hashlib import sha1

latin = lambda x: x.encode('latin')

def write_bootimg(output, kernel, ramdisk, second, dtimg,
        name, cmdline, kernel_addr, ramdisk_addr, second_addr, tags_addr, page_size, padding_size, os_version):
    ''' make C8600-compatible bootimg.
        output: file object
        kernel, ramdisk, second: file object or string
        name, cmdline: string
        base, page_size, padding_size: integer size

        official document:
        https://android.googlesource.com/platform/system/core/+/master/mkbootimg/bootimg.h

        Note: padding_size is not equal to page_size in HuaWei C8600
    '''
    if not isinstance(page_size, int):
        page_size = 0x800

    if not isinstance(padding_size, int):
        padding_size = 0x800

    if not hasattr(output, 'write'):
        output = sys.stdout

    padding = lambda x: struct.pack('%ds' % ((~x + 1) & (padding_size - 1)), latin(''))

    def getsize(x):
        if x is None:
            return 0
        assert hasattr(x, 'seek')
        assert hasattr(x, 'tell')
        x.seek(0, 2)
        return x.tell()

    def writecontent(output, x):
        if x is None:
            # sha.update('')
            sha.update(struct.pack('<I', 0))
            return None

        assert hasattr(x, 'read')

        x.seek(0, 0)
        content = x.read()
        sha.update(content)
        sha.update(struct.pack('<I', len(content)))
        output.write(content)
        output.write(padding(x.tell()))

        if hasattr(x, 'close'):
            x.close()

    output.write(struct.pack('<8s10I16s512s', latin('ANDROID!'),
        getsize(kernel), kernel_addr,
        getsize(ramdisk), ramdisk_addr,
        getsize(second), second_addr,
        tags_addr, page_size, getsize(dtimg), os_version,
        name, cmdline))

    idpos = output.tell()
    # fill with null first
    output.write(struct.pack('32s', latin('')))
    output.write(padding(output.tell()))
    sha = sha1()
    writecontent(output, kernel)
    writecontent(output, ramdisk)
    writecontent(output, second)
    writecontent(output, dtimg)
    # fill back sha1
    output.seek(idpos, 0)
    output.write(sha.digest())
    if hasattr('output', 'close'):
        output.close()

def parse_bootimg(bootimg):
    ''' parse C8600-compatible bootimg.
        write kernel to kernel[.gz]
        write ramdisk to ramdisk[.gz]
        write second to second[.gz]
        write dtimg to dt.img
        write extra to unknown

        official document:
        https://android.googlesource.com/platform/system/core/+/master/mkbootimg/bootimg.h

        Note: padding_size is not equal to page_size in HuaWei C8600
    '''

    (   magic,
        kernel_size, kernel_addr,
        ramdisk_size, ramdisk_addr,
        second_size, second_addr,
        tags_addr, page_size, dt_size, os_version,
        name, cmdline, id4x8
    ) = struct.unpack('<8s10I16s512s32s', bootimg.read(608))
    bootimg.seek(page_size - 608, 1)

    base = kernel_addr - 0x00008000
    assert magic.decode('latin') == 'ANDROID!', 'invald bootimg'
    # assert base == ramdisk_addr - 0x01000000, 'invalid bootimg'
    # assert base == second_addr - 0x00f00000, 'invalid bootimg'
    # assert base == tags_addr - 0x00000100, 'invalid bootimg'

    def say(v):
        b7 = 127
        b4 = 15
        a = (v >> 25) & b7
        b = (v >> 18) & b7
        c = (v >> 11) & b7
        y = ((v >>  4) & b7) + 2000
        m = v & b4
        return '%d.%d.%d %s-%s' % (a, b, c, y, m)
    sys.stderr.write('kernel_addr=0x%x\n' % kernel_addr)
    sys.stderr.write('ramdisk_addr=0x%x\n' % ramdisk_addr)
    sys.stderr.write('second_addr=0x%x\n' % second_addr)
    sys.stderr.write('tags_addr=0x%x\n' % tags_addr)
    # sys.stderr.write('base=0x%x\n' % base)
    sys.stderr.write('page_size=%d\n' % page_size)
    sys.stderr.write('os_version=0x%08x(%s)\n' % (os_version, say(os_version)))
    sys.stderr.write('name="%s"\n' % name.decode('latin').strip('\x00'))
    sys.stderr.write('cmdline="%s"\n' % cmdline.decode('latin').strip('\x00'))

    while True:
        if bootimg.read(page_size) == struct.pack('%ds' % page_size, latin('')):
            continue
        bootimg.seek(-page_size, 1)
        size = bootimg.tell()
        break

    padding = lambda x: (~x + 1) & (size - 1)
    sys.stderr.write('padding_size=%d\n' % size)
    metadata = {
        'kernel_addr': kernel_addr,
        'ramdisk_addr': ramdisk_addr,
        'second_addr': second_addr,
        'tags_addr': tags_addr,
        'page_size': page_size,
        'name': name.decode('latin').strip('\x00'),
        'cmdline': cmdline.decode('latin').strip('\x00'),
        'padding_size': size,
        'os_version': os_version,
    }
    w = open('bootimg.json', 'w')
    w.write(json.dumps(metadata))
    w.close()

    gzname = lambda x: x == struct.pack('3B', 0x1f, 0x8b, 0x08) and '.gz' or ''

    kernel = bootimg.read(kernel_size)
    output = open('kernel%s' % gzname(kernel[:3]) , 'wb')
    magic = struct.pack('>I', 0xd00dfeed)
    pos = kernel.find(magic)
    if pos > 0:
        output.write(kernel[:pos])
        kerneldt = open('kernel%s.dt' % gzname(kernel[:3]) , 'wb')
        kerneldt.write(kernel[pos:])
        kerneldt.close()
    else:
        output.write(kernel)
    output.close()
    bootimg.seek(padding(kernel_size), 1)

    ramdisk = bootimg.read(ramdisk_size)
    output = open('ramdisk%s' % gzname(ramdisk[:3]) , 'wb')
    output.write(ramdisk)
    output.close()
    bootimg.seek(padding(ramdisk_size), 1)

    if second_size:
        second = bootimg.read(second_size)
        output = open('second%s' % gzname(second[:3]) , 'wb')
        output.write(second)
        output.close()
        bootimg.seek(padding(second_size), 1)

    if dt_size:
        dtimg = bootimg.read(dt_size)
        output = open('dt.img', 'wb')
        output.write(dtimg)
        output.close()
        bootimg.seek(padding(dt_size), 1)

    unknown = bootimg.read()
    if unknown:
        output = open('unknown', 'wb')
        output.write(unknown)
        output.close()
    elif os.path.exists('unknown'):
        os.unlink('unknown')

    bootimg.close()

# CRC CCITT
crc_ccitt_table = []
for crc in range(0, 256):
    for x in range(0, 8):
        if crc & 0x1:
            crc = (crc >> 1) ^ 0x8408
        else:
            crc >>= 1
    crc_ccitt_table.append(crc)

def crc_ccitt(data, crc=0xffff):
    for item in data:
        crc = (crc >> 8) ^ crc_ccitt_table[crc & 0xff ^ item]
    return crc

def get_crc_ccitt(data):
    crc = crc_ccitt(data) ^ 0xffff
    return struct.pack('<H', crc)

POSITION = {0x30000000: 'boot.img',
            0x40000000: 'system.img',
            0x50000000: 'userdata.img',
            0x60000000: 'recovery.img',
            0xf2000000: 'splash.565',}
def parse_updata(updata, debug=False):
    ''' parse C8600 UPDATA binary.
        if debug is true or 1 or yes, write content to [position], else according POSITION

        UPDATA.APP Structure (only guess)
        magic                   |       0x55 0xaa 0x5a 0xa5
        header_length           |       unsigned int
        tag1                    |       0x01 0x00 0x00 0x00
        boardname               |       char[8]
        position                |       unsigned int
        content_length          |       unsigned int
        date                    |       char[16] -> YYYY.MM.DD
        time                    |       char[16] -> hh.mm.ss
        INPUT                   |       char[16] -> INPUT
        null                    |       char[16]
        crc                     |       crc-ccitt for header (98bit)
        tag2                    |       0x00 0x10 0x00 0x00
        header                  |       crc-ccitt for every 4096 of content
        content                 |
        padding                 |       padding to 4 bytes
    '''

    updatalist = open('updatalist.txt', 'w')
    while True:
        data = updata.read(4)
        if not data:
            break
        if data == struct.pack('4s', latin('')):
            continue

        data += updata.read(94)
        assert len(data) == 98, 'invalid updata'
        (   magic,
            header_length,
            tag1,       # \x01\x00\x00\x00
            boardname,
            position,
            content_length,
            date,
            time,
            INPUT,
            null,
            crc,
            tag2,       # \x00\x10\x00\x00
        ) = struct.unpack('<4sI4s8sII16s16s16s16s2s4s', data)

        magic, = struct.unpack('!I', magic)
        assert magic == 0x55aa5aa5, 'invalid updata %x' % magic

        header_header = list(struct.unpack('98B', data))
        header_header[-5] = header_header[-6] = 0
        assert crc == get_crc_ccitt(header_header)

        open('boardname.bin', 'wb').write(boardname)
        open('date.txt', 'wb').write(date)
        open('time.txt', 'wb').write(time)

        padding = (~(header_length + content_length) + 1) & 3

        remain = header_length - 98
        header = list(struct.unpack('%dB' % remain, updata.read(remain)))

        output = open(POSITION.get(position, '0x%x.raw' % position), 'wb')
        sys.stderr.write('%s\t0x%x\n' % (output.name, position))
        updatalist.write('%s\t0x%x\n' % (output.name, position))

        remain = content_length
        while remain > 0:
            size = remain > 4096 and 4096 or remain
            data = updata.read(size)
            if debug:
                check = list(struct.unpack('%dB' % size, data))
                check.append(header.pop(0))
                check.append(header.pop(0))
                assert crc_ccitt(check) == 0xf0b8
            output.write(data)
            remain -= size
        output.close()

        updata.seek(padding, 1)

    updata.close()
    updatalist.close()

def write_updata(output):
    '''
        magic                   |       0x55 0xaa 0x5a 0xa5
        header_length           |       unsigned int
        tag1                    |       0x01 0x00 0x00 0x00
        boardname               |       char[8]
        position                |       unsigned int
        content_length          |       unsigned int
        date                    |       char[16] -> YYYY.MM.DD
        time                    |       char[16] -> hh.mm.ss
        INPUT                   |       char[16] -> INPUT
        null                    |       char[16]
        crc                     |       crc-ccitt for header (98bit)
        tag2                    |       0x00 0x10 0x00 0x00
        header                  |       crc-ccitt for every 4096 of content
        content                 |
        padding                 |       padding to 4 bytes
    '''
    from time import strftime

    output.write(struct.pack('1s', latin('')) * 92)
    updatalist = open('updatalist.txt', 'r')
    boardname = open('boardname.bin', 'rb').read()
    if os.path.isfile('date.txt'):
        date = open('date.txt').read()
    else:
        date = strftime('%Y.%m.%d')
    if os.path.isfile('time.txt'):
        time = open('time.txt').read()
    else:
        time = strftime('%H.%M.%S')
    for record in updatalist:
        name, position = record.split()[:2]
        data = open(name, 'rb')
        header = latin('')
        content_length = 0
        while True:
            raw4096 = data.read(4096)
            content_length += len(raw4096)
            if not raw4096:
                break
            header += get_crc_ccitt(list(struct.unpack('%dB' % len(raw4096), raw4096)))
        header_length = 98
        header_length += len(header)
        data.close()

        header_header = struct.pack('<4sI4s8sII16s16s16s16s2s4s',
                latin('\x55\xaa\x5a\xa5'),
                header_length,
                latin('\x01\x00\x00\x00'),
                boardname,
                int(position, 16),
                content_length,
                latin(date),
                latin(time),
                latin('INPUT'),
                latin(''),
                latin(''),
                latin('\x00\x10\x00\x00'))
        crc = get_crc_ccitt(list(struct.unpack('98B', header_header)))
        output.write(header_header[:-6])
        output.write(crc)
        output.write(header_header[-4:])
        output.write(header)
        data = open(name, 'rb')
        output.write(data.read())
        data.close()
        padding = (~(header_length + content_length) + 1) & 3
        output.write(struct.pack('%ds' % padding, latin('')))
    output.close()

def cpio_list(directory, output=None):
    ''' generate gen_cpio_init-compatible list for directory,
        if output is None, write to stdout

        official document:
        http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=blob;f=usr/gen_init_cpio.c
    '''

    if not hasattr(output, 'write'):
        output = sys.stdout
    for root, dirs, files in os.walk(directory):
        for file in dirs + files:
            path = os.path.join(root, file)
            info = os.lstat(path)
            name = path.replace(directory, '', 1)
            name = name.replace(os.sep, '/')    # for windows
            if name[:1] != '/':
                name = '/' + name
            mode = oct(S_IMODE(info.st_mode))
            if S_ISLNK(info.st_mode):
                # slink name path mode uid gid
                realpath = os.readlink(path)
                output.write('slink %s %s %s 0 0\n' % (name, realpath, mode))
            elif S_ISDIR(info.st_mode):
                # dir name path mode uid gid
                output.write('dir %s %s 0 0\n' % (name, mode))
            elif S_ISREG(info.st_mode):
                # file name path mode uid gid
                output.write('file %s %s %s 0 0\n' % (name, path, mode))

    if hasattr(output, 'close'):
        output.close()

def parse_cpio(cpio, directory, cpiolist):
    ''' parse cpio, write content under directory.
        cpio: file object
        directory: string
        cpiolist: file object

        official document: (cpio newc structure)
        http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=blob;f=usr/gen_init_cpio.c
    '''

    padding = lambda x: (~x + 1) & 3

    def read_cpio_header(cpio):
        assert cpio.read(6).decode('latin') == '070701', 'invalid cpio'
        cpio.read(8) # ignore inode number
        mode = int(cpio.read(8), 16)
        cpio.read(8) # uid
        cpio.read(8) # gid
        cpio.read(8) # nlink
        cpio.read(8) # timestamp
        filesize = int(cpio.read(8), 16)
        cpio.read(8) # major
        cpio.read(8) # minor
        cpio.read(8) # rmajor
        cpio.read(8) # rminor
        namesize = int(cpio.read(8), 16)
        cpio.read(8)
        name = cpio.read(namesize - 1).decode('latin') # maybe utf8?
        cpio.read(1)
        cpio.read(padding(namesize + 110))
        return name, mode, filesize

    while True:
        name, mode, filesize = read_cpio_header(cpio)
        if name == 'TRAILER!!!':
            break

        if name[:1] != '/':
            name = '/%s' % name

        name = os.path.normpath(name)
        path = '%s%s' %(directory, name)
        name = name.replace(os.sep, '/') # for windows

        srwx = oct(S_IMODE(mode))
        if S_ISLNK(mode):
            location = cpio.read(filesize)
            cpio.read(padding(filesize))
            cpiolist.write('slink %s %s %s\n' % (name, location, srwx))
        elif S_ISDIR(mode):
            try: os.makedirs(path)
            except os.error: pass
            cpiolist.write('dir %s %s\n' % (name, srwx))
        elif S_ISREG(mode):
            dirname = os.path.dirname(path)
            if not os.path.isdir(dirname):
                os.makedirs(dirname)
            tmp = open(path, 'wb')
            tmp.write(cpio.read(filesize))
            cpio.read(padding(filesize))
            tmp.close()
            cpiolist.write('file %s %s %s\n' % (name, path, srwx))
        else:
            cpio.read(filesize)
            cpio.read(padding(filesize))

    cpio.close()
    cpiolist.close()

def write_cpio(cpiolist, output):
    ''' generate cpio from cpiolist.
        cpiolist: file object
        output: file object
    '''

    padding = lambda x, y: struct.pack('%ds' % ((~x + 1) & (y - 1)), latin(''))

    def write_cpio_header(output, name, mode=0, nlink=1, filesize=0):
        namesize = len(name) + 1
        output.write(latin('070701'))
        output.write(latin('%08x' % 0)) # ino normally only for hardlink
        output.write(latin('%08x' % mode))
        output.write(latin('%08x%08x' % (0, 0))) # uid, gid set to 0
        output.write(latin('%08x' % nlink))
        output.write(latin('%08x' % 0)) # timestamp set to 0
        output.write(latin('%08x' % filesize))
        output.write(latin('%08x%08x' % (3, 1)))
        output.write(latin('%08x%08x' % (0, 0))) # dont support rmajor, rminor
        output.write(latin('%08x' % namesize))
        output.write(latin('%08x' % 0)) # chksum always be 0
        output.write(latin(name))
        output.write(struct.pack('1s', latin('')))
        output.write(padding(namesize + 110, 4))

    def cpio_mkfile(output, name, path, mode, *kw):
        if os.path.split(name)[1] in ('su', 'busybox'):
            mode = '4555'
        mode = int(mode, 8) | S_IFREG
        filesize = os.path.getsize(path)
        write_cpio_header(output, name, mode, 1, filesize)
        tmp = open(path, 'rb')
        output.write(tmp.read())
        tmp.close()
        output.write(padding(filesize, 4))

    def cpio_mkdir(output, name, mode='755', *kw):
        if name == '/tmp':
            mode = '1777'
        mode = int(mode, 8) | S_IFDIR
        write_cpio_header(output, name, mode, 2, 0)

    def cpio_mkslink(output, name, path, mode='777', *kw):
        mode = int(mode, 8) | S_IFLNK
        filesize = len(path)
        write_cpio_header(output, name, mode, 1, filesize)
        output.write(latin(path))
        output.write(padding(filesize, 4))

    def cpio_mknod(output, *kw):
        sys.stderr.write('nod is not implemented\n')

    def cpio_mkpipe(output, *kw):
        sys.stderr.write('pipe is not implemented\n')

    def cpio_mksock(output, *kw):
        sys.stderr.write('sock is not implemented\n')

    def cpio_tailer(output):
        name = 'TRAILER!!!'
        write_cpio_header(output, name)

        # normally, padding is ignored by decompresser
        if hasattr(output, 'tell'):
            output.write(padding(output.tell(), 512))

    files = []
    functions = {'dir': cpio_mkdir,
                 'file': cpio_mkfile,
                 'slink': cpio_mkslink,
                 'nod': cpio_mknod,
                 'pipe': cpio_mkpipe,
                 'sock': cpio_mksock}
    while True:
        line = cpiolist.readline()
        if not line:
            break
        lines = line.split()
        if len(lines) < 1 or lines[0] == '#':
            continue
        function = functions.get(lines[0])
        if not function:
            continue
        lines.pop(0)
        lines[0] = lines[0].replace(os.sep, '/') # if any
        if lines[0] in files:
            sys.stderr.write('ignore duplicate %s\n' % lines[0])
            continue
        files.append(lines[0])
        function(output, *lines)

    # for extra in ['/tmp', '/mnt']:
    #    if extra not in files:
    #        sys.stderr.write('add extra %s\n' % extra)
    #        cpio_mkdir(output, extra)

    cpio_tailer(output)
    cpiolist.close()
    output.close()

def parse_yaffs2(image, directory):
    ''' parse yaffs2 image.

        official document: (utils/mkyaffs2image)
        https://android.googlesource.com/platform/external/yaffs2/+/master/yaffs2/
        spare: yaffs_PackedTags2 in yaffs_packedtags2.h
        chunk: yaffs_ExtendedTags in yaffs_guts.h
    '''

    path = '.'
    filelist = {1: '.'}

    class Complete(Exception):
        pass

    def read_chunk(image):
        chunk = image.read(2048)
        spare = image.read(64)
        if not chunk:
            raise Complete
        assert len(spare) >= 16
        return chunk, spare

    def process_chunk(image):
        chunk, spare = read_chunk(image)

        nil, objectid, nil, bytecount = struct.unpack('<4I', spare[:16])

        if bytecount == 0xffff:
            assert len(chunk) >= 460
            (   filetype, parent,
                nil, name, padding, mode,
                uid, gid, atime, mtime, ctime,
                filesize, equivalent, alias
            ) = struct.unpack('<iiH256s2sI5Iii160s', chunk[:460])

            # only for little-endian
            # (   filetype, parent,
            #     nil, name, mode,
            #     uid, gid, atime, mtime, ctime,
            #     filesize, equivalent, alias
            # ) = struct.unpack('iiH256sI5Iii160s', chunk[:460])

            parent = filelist.get(parent)
            assert parent is not None

            name = name.decode('latin').split('\x00')[0]
            path = name and '%s/%s' % (parent, name) or parent
            filelist[objectid] = path
            fullname = '%s/%s' % (directory, path)

            if filetype == 0: # unknown
                pass
            elif filetype == 1: # file
                flag = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
                if hasattr(os, 'O_BINARY'):
                    flag |= os.O_BINARY
                output = os.open(fullname, flag, mode)
                while filesize > 0:
                    chunk, spare = read_chunk(image)
                    nil, nil, nil, bytecount = struct.unpack('<4I', spare[:16])
                    size = filesize < bytecount and filesize or bytecount
                    os.write(output, chunk[:size])
                    filesize -= size
                os.close(output)
            elif filetype == 2: # slink
                alias = alias.decode('latin').split('\x00')[0]
                try: os.symlink(alias, fullname)
                except: sys.stderr.write('soft %s -> %s\n' % (fullname, alias))
            elif filetype == 3: # dir
                if not os.path.isdir(fullname):
                    os.makedirs(fullname, mode)
                try: os.chmod(fullname, mode)
                except: sys.stderr.write('directory mode is not supported')
            elif filetype == 4: # hlink
                link = filelist.get(equivalent)
                try: os.link(filelist.get(equivalent), fullname)
                except: sys.stderr.write('hard %s -> %s\n' % (fullname, link))
            elif filetype == 5: # special
                pass

    while True:
        try: process_chunk(image)
        except Complete: break

    image.close()

from gzip import GzipFile
class CPIOGZIP(GzipFile):
    # dont write filename
    def _write_gzip_header(self):
        self.fileobj.write(struct.pack('4B', 0x1f, 0x8b, 0x08, 0x00))
        self.fileobj.write(struct.pack('4s', latin('')))
        self.fileobj.write(struct.pack('2B', 0x00, 0x03))

    # don't check crc and length
    def _read_eof(self):
        pass

def parse_rle(rle, raw):
    ''' convert 565-rle format to raw file.

        official document:
        https://android.googlesource.com/platform/build/+/master/tools/rgb2565/to565.c
    '''
    r = lambda x: int(((x >> 11) & 0x1f) << 3)
    g = lambda x: int(((x >> 5) & 0x3f) << 2)
    b = lambda x: int((x & 0x1f) << 3)

    total = 0
    while True:
        data = rle.read(4)
        if not data:
            break
        assert len(data) == 4
        count, color = struct.unpack('<2H', data)
        total += count
        while count:
            count -= 1
            raw.write(struct.pack('3B', r(color), g(color), b(color)))
    rle.close()
    raw.close()
    return total

def parse_565(rle, raw):
    ''' convert 565 format to raw file.

        official document:
        https://android.googlesource.com/platform/build/+/master/tools/rgb2565/to565.c
    '''
    r = lambda x: int(((x >> 11) & 0x1f) << 3)
    g = lambda x: int(((x >> 5) & 0x3f) << 2)
    b = lambda x: int((x & 0x1f) << 3)

    total = 0
    while True:
        data = rle.read(2)
        if not data:
            break
        assert len(data) == 2
        color, = struct.unpack('<H', data)
        total += 1
        raw.write(struct.pack('3B', r(color), g(color), b(color)))
    rle.close()
    raw.close()
    return total

def write_rle(raw, rle):
    ''' convert raw file to 565-rle format.
    '''
    x = lambda r, g, b: ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)

    last = None
    total = 0
    while True:
        rgb = raw.read(3)
        if not rgb:
            break
        total += 1
        assert len(rgb) == 3
        color = x(*struct.unpack('3B', rgb))
        if last is None:
            pass
        elif color == last and count != 0xffff:
            count += 1
            continue
        else:
            rle.write(struct.pack('<2H', count, last))
        last = color
        count = 1
    if count:
        rle.write(struct.pack('<2H', count, last))
    raw.close()
    rle.close()
    return total

def write_565(raw, rle):
    ''' convert raw file to 565 format.
    '''
    x = lambda r, g, b: ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)

    last = None
    total = 0
    while True:
        rgb = raw.read(3)
        if not rgb:
            break
        total += 1
        assert len(rgb) == 3
        color = x(*struct.unpack('3B', rgb))
        rle.write(struct.pack('<H', color))
    raw.close()
    rle.close()
    return total

def unpack_simg(simg=None, img=None):
    '''unpack sparse image

    official document:
    https://android.googlesource.com/platform/system/core/+/master/libsparse/
    '''
    sys.stderr.write('arguments: [sparse image] [raw image]\n')
    sys.stderr.write('simg file: %s\n' % simg)
    sys.stderr.write(' img file: %s\n' % img)
    if simg is None or img is None:
        return False

    SPARSE_HEADER_MAJOR_VER = 1
    SPARSE_HEADER_LEN = 28
    CHUNK_HEADER_LEN = 12
    CHUNK_TYPE_RAW = 0xCAC1
    CHUNK_TYPE_FILL = 0xCAC2
    CHUNK_TYPE_DONT_CARE = 0xCAC3
    CHUNK_TYPE_CRC32 = 0xCAC4
    NULL = latin('')

    class SparseImageError(Exception):
        pass

    magic = struct.pack('<I', 0xed26ff3a)
    wb = open(img, 'wb')
    rb = open(simg, 'rb+')
    mm = mmap.mmap(rb.fileno(), 0)
    pos = -1
    while True:
        pos = mm.find(magic, pos + 1)
        if pos < 0:
            break
        mm.seek(pos, 0)
        (
            _,
            major_version,
            minor_version,
            file_hdr_sz,
            chunk_hdr_sz,
            blk_sz,
            total_blks,
            total_chunks,
            image_checksum
        ) = struct.unpack('<I4H4I', mm.read(SPARSE_HEADER_LEN))
        if major_version != SPARSE_HEADER_MAJOR_VER:
            continue
        if file_hdr_sz < SPARSE_HEADER_LEN:
            continue
        if chunk_hdr_sz < CHUNK_HEADER_LEN:
            continue

        # finally, get it
        if file_hdr_sz > SPARSE_HEADER_LEN:
            mm.seek(file_hdr_sz - SPARSE_HEADER_LEN, 1)
        for _ in range(0, total_chunks):
            (
                chunk_type,
                reserved,
                chunk_sz,
                total_sz
            ) = struct.unpack('<2H2I', mm.read(CHUNK_HEADER_LEN))
            if file_hdr_sz > SPARSE_HEADER_LEN:
                mm.seek(file_hdr_sz - SPARSE_HEADER_LEN, 1)
            chunk_data_size = total_sz - chunk_hdr_sz
            chunk_block_size = chunk_sz * blk_sz
            if chunk_type == CHUNK_TYPE_RAW:
                if chunk_data_size != chunk_block_size:
                    raise SparseImageError()
                while chunk_data_size > 0:
                    if chunk_data_size > 8192:
                        size = 8192
                    else:
                        size = chunk_data_size
                    chunk_data_size -= size
                    wb.write(mm.read(size))
            elif chunk_type == CHUNK_TYPE_FILL:
                if chunk_data_size != 4:
                    raise SparseImageError()
                while chunk_block_size > 0:
                    if chunk_block_size > 8192:
                        size = 8192
                    else:
                        size = chunk_block_size
                    chunk_block_size -= size
                    wb.write(mm.read(4) * (size / 4))
            elif chunk_type == CHUNK_TYPE_DONT_CARE:
                if chunk_data_size != 0:
                    raise SparseImageError()
                while chunk_block_size > 0:
                    if chunk_block_size > 8192:
                        size = 8192
                    else:
                        size = chunk_block_size
                    chunk_block_size -= size
                    wb.write(struct.pack('%ss' % size, NULL))
            elif chunk_type == CHUNK_TYPE_CRC32:
                if chunk_data_size != 4:
                    raise SparseImageError()
                mm.read(4)
            else:
                raise SparseImageError()
        # should break?
        pos = mm.tell()

    rb.close()
    wb.close()

__all__ = [ 'parse_updata',
            'write_updata',
            'parse_bootimg',
            'write_bootimg',
            'parse_cpio',
            'write_cpio',
            'parse_yaffs2',
            'parse_rle',
            'write_rle',
            'parse_565',
            'write_565',
            'cpio_list',
            'POSITION',
            'unpack_simg',
            ]

# above is the module of bootimg
# below is only for usage...

def repack_bootimg(kernel_addr=None, ramdisk_addr=None, second_addr=None, tags_addr=None, cmdline=None, page_size=None, padding_size=None):

    if os.path.exists('ramdisk.cpio.gz'):
        ramdisk = 'ramdisk.cpio.gz'
    else:
        ramdisk = 'ramdisk.gz'

    if os.path.exists('second.gz'):
        second = 'second.gz'
    elif os.path.exists('second'):
        second = 'second'
    else:
        second = ''

    if os.path.exists('dt.img'):
        dtimg = 'dt.img'
    else:
        dtimg = ''

    sys.stderr.write('arguments: [kernel_addr] [ramdisk_addr] [second_addr] [tags_addr] [cmdline] [page_size] [padding_size]\n')
    metadata = {}
    if os.path.exists('bootimg.json'):
        try:
            metadata = json.loads(open('bootimg.json').read())
        except:
            pass

    if 'kernel_addr' in metadata:
        kernel_addr = metadata.get('kernel_addr', 0)
    else:
        kernel_addr = int(kernel_addr, 16)

    if 'ramdisk_addr' in metadata:
        ramdisk_addr = metadata.get('ramdisk_addr', 0)
    else:
        ramdisk_addr = int(ramdisk_addr, 16)

    if 'second_addr' in metadata:
        second_addr = metadata.get('second_addr', 0)
    else:
        second_addr = int(second_addr, 16)

    if 'tags_addr' in metadata:
        tags_addr = metadata.get('tags_addr', 0)
    else:
        tags_addr = int(tags_addr, 16)

    if 'name' in metadata:
        name = latin(metadata.get('name'))
    elif name is None:
        name = latin('')

    if 'cmdline' in metadata:
        cmdline = latin(metadata.get('cmdline'))
    elif cmdline is None:
        cmdline = latin('mem=211M console=null androidboot.hardware=qcom')

    if 'page_size' in metadata:
        page_size = metadata.get('page_size', 2048)
    else:
        page_size = int(str(page_size))

    if 'padding_size' in metadata:
        padding_size = metadata.get('padding_size', 4096)
    else:
        padding_size = int(str(padding_size))

    os_version = metadata.get('os_version', 0)

    sys.stderr.write('kernel: kernel\n')
    sys.stderr.write('ramdisk: %s\n' % ramdisk)
    sys.stderr.write('second: %s\n' % second)
    sys.stderr.write('dtimg: %s\n' % dtimg)
    sys.stderr.write('kernel_addr: 0x%x\n' % kernel_addr)
    sys.stderr.write('ramdisk_addr: 0x%x\n' % ramdisk_addr)
    sys.stderr.write('second_addr: 0x%x\n' % second_addr)
    sys.stderr.write('tags_addr: 0x%x\n' % tags_addr)
    sys.stderr.write('name: %s\n' % name)
    sys.stderr.write('cmdline: %s\n' % cmdline)
    sys.stderr.write('page_size: %d\n' % page_size)
    sys.stderr.write('padding_size: %d\n' % padding_size)
    sys.stderr.write('output: boot_repack.img\n')

    if os.path.isfile('kernel.gz'):
        kernel = open('kernel.gz', 'rb')
    else:
        kernel = open('kernel', 'rb')
    if os.path.isfile(kernel.name + '.dt'):
        dt = open(kernel.name + '.dt', 'rb')

        kerneldt = open(kernel.name + '.bundle', 'wb')
        kerneldt.write(kernel.read())
        kerneldt.write(dt.read())
        kerneldt.close()

        dt.close()
        kernel.close()
        kernel = open(kerneldt.name, 'rb')
    options = { 'kernel_addr': kernel_addr,
                'ramdisk_addr': ramdisk_addr,
                'second_addr': second_addr,
                'tags_addr': tags_addr,
                'name': name,
                'cmdline': cmdline,
                'output': open('boot_repack.img', 'wb'),
                'kernel': kernel,
                'ramdisk': open(ramdisk, 'rb'),
                'second': second and open(second, 'rb') or None,
                'dtimg': dtimg and open(dtimg, 'rb') or None,
                'page_size': page_size,
                'padding_size': padding_size,
                'os_version': os_version,
                }
    write_bootimg(**options)
    if kernel.name.endswith('.bundle'):
        os.remove(kernel.name)

def unpack_bootimg(bootimg=None):
    if bootimg is None:
        bootimg = 'boot.img'
    sys.stderr.write('arguments: [bootimg file]\n')
    sys.stderr.write('bootimg file: %s\n' % bootimg)
    sys.stderr.write('output: kernel[.gz] ramdisk[.gz] second[.gz]\n')
    parse_bootimg(open(bootimg, 'rb'))

def unpack_updata(updata=None, debug=False):
    if updata is None and os.path.exists('UPDATA.APP'):
        updata = 'UPDATA.APP'
    sys.stderr.write('arguments: [updata file]\n')
    sys.stderr.write('updata file: %s\n' % updata)
    sys.stderr.write('output: splash.565 (565 file)\n')
    sys.stderr.write('output: boot.img recover.img (bootimg file)\n')
    sys.stderr.write('output: system.img userdata.img (yaffs2 image)\n')
    parse_updata(open(updata, 'rb'), debug)

def unpack_ramdisk(ramdisk=None, directory=None):
    if ramdisk is None:
        ramdisk = 'ramdisk.gz'

    if directory is None:
        directory = 'initrd'

    sys.stderr.write('arguments: [ramdisk file] [directory]\n')
    sys.stderr.write('ramdisk file: %s\n' % ramdisk)
    sys.stderr.write('directory: %s\n' % directory)
    sys.stderr.write('output: cpiolist.txt\n')

    if os.path.lexists(directory):
        raise SystemExit('please remove %s' % directory)

    tmp = open(ramdisk, 'rb')
    magic = tmp.read(6)
    if magic[:3] == struct.pack('3B', 0x1f, 0x8b, 0x08):
        tmp.close()
        cpio = CPIOGZIP(ramdisk, 'rb')
    elif magic.decode('latin') == '070701':
        tmp.seek(0, 0)
        cpio = tmp
    else:
        tmp.close()
        raise IOError('invalid ramdisk')

    cpiolist = open('cpiolist.txt', 'w')
    parse_cpio(cpio, directory, cpiolist)

def repack_updata(updatalist=None, debug=False):
    if updatalist is None:
        updatalist = 'updatalist.txt'
    sys.stderr.write('arguments: [updatalist file]\n')
    sys.stderr.write('updatalist file: %s\n' % updatalist)
    sys.stderr.write('output: updata_repack.app\n')
    output = open('updata_repack.app', 'wb')
    write_updata(output)

def repack_ramdisk(cpiolist=None):
    if cpiolist is None:
        cpiolist = 'cpiolist.txt'

    sys.stderr.write('arguments: [cpiolist file]\n')
    sys.stderr.write('cpiolist file: %s\n' % cpiolist)
    sys.stderr.write('output: ramdisk.cpio.gz\n')

    cpiogz = CPIOGZIP('ramdisk.cpio.gz', 'wb')
    output = open(cpiolist, 'r')
    write_cpio(output, cpiogz)
    cpiogz.close()

def unpack_yaffs(image=None, directory=None):
    if image is None:
        image = 'userdata.img'
    if directory is None and image[-4:] == '.img':
        directory = image[:-4]

    sys.stderr.write('arguments: [yaffs2 image] [directory]\n')
    sys.stderr.write('yaffs2 image: %s\n' % image)
    sys.stderr.write('directory: %s\n' % directory)

    if os.path.lexists(directory):
        raise SystemExit('please remove %s' % directory)

    parse_yaffs2(open(image, 'rb'), directory)

SIZE = {320*480: (320, 480),        # HVGA
        240*320: (240, 320),        # QVGA
        240*400: (240, 400),        # WQVGA400
        240*432: (240, 432),        # WQVGA432
        480*800: (480, 800),        # WVGA800
        480*854: (480, 854),        # WVGA854
        }
def unpack_rle_565(rlefile, rawfile, function):
    if rawfile is None:
        if rlefile[-4] == '.':
            rawfile = rlefile[:-4] + '.raw'
        else:
            rawfile = rlefile + '.raw'

    if rawfile[-4] == '.':
        pngfile = rawfile[:-4] + '.png'
    else:
        pngfile = rawfile + '.png'

    sys.stderr.write('output: %s [%s]\n' % (rawfile, pngfile))

    rle = open(rlefile, 'rb')
    raw = open(rawfile, 'wb')
    total = function(rle, raw)

    try: import Image
    except ImportError: return

    size = SIZE.get(total)
    if size is None: return

    data = open(rawfile, 'rb')
    Image.fromstring('RGB',  size, data.read(), 'raw').save(pngfile)
    data.close()

def unpack_rle(rlefile=None, rawfile=None):
    if rlefile is None:
        rlefile = 'initlogo.rle'
    sys.stderr.write('arguments: [rle file] [raw file]\n')
    sys.stderr.write('rle file: %s\n' % (rlefile))
    unpack_rle_565(rlefile, rawfile, parse_rle)

def unpack_565(rlefile=None, rawfile=None):
    if rlefile is None:
        rlefile = 'splash.565'
    sys.stderr.write('arguments: [565 file] [raw file]\n')
    sys.stderr.write('565 file: %s\n' % (rlefile))
    unpack_rle_565(rlefile, rawfile, parse_565)

def repack_rle_565(rawfile, rlefile, function):

    if rawfile[-4:] != '.raw':
        try: import Image
        except ImportError:
            sys.stderr.write('Please Install PIL (python-imaging)\n')
            return None
        try:
            img = Image.open(rawfile)
        except:
            sys.stderr.write('Cannot Open Image File')
            return None

        from JpegImagePlugin import RAWMODE
        if 'transparency' in img.info or img.mode == 'RGBA':
            new = img.mode == 'RGBA' and img or img.convert('RGBA')
            img = Image.new('RGB', new.size)
            img.paste(new, (0, 0), new)
        elif img.mode not in RAWMODE:
            img = img.convert('RGB')

        if img.size not in list(SIZE.values()):
            sys.stderr.write('warning: Image is not HVGA, [W]QVGA, WVGA\n')

        rawfile = rlefile[:-4] + '.raw'
        data = open(rawfile, 'wb')
        data.write(img.tostring())
        data.close()

    raw = open(rawfile, 'rb')
    rle = open(rlefile, 'wb')
    function(raw, rle)

def repack_rle(rawfile=None, rlefile=None):
    if rawfile is None:
        rawfile = 'initlogo.raw'

    if rlefile is None:
        if rawfile[-4] == '.':
            rlefile = rawfile[:-4] + '.rle'
        else:
            rlefile = rawfile + '.rle'

    sys.stderr.write('arguments: [raw file] [rle file]\n')
    sys.stderr.write('raw file: %s\n' % rawfile)
    sys.stderr.write('rle file: %s\n' % rlefile)
    repack_rle_565(rawfile, rlefile, write_rle)

def repack_565(rawfile=None, rlefile=None):
    if rawfile is None:
        rawfile = 'splash.raw'

    if rlefile is None:
        if rawfile[-4] == '.':
            rlefile = rawfile[:-4] + '.565'
        else:
            rlefile = rawfile + '.565'

    sys.stderr.write('arguments: [raw file] [565 file]\n')
    sys.stderr.write('raw file: %s\n' % rawfile)
    sys.stderr.write('565 file: %s\n' % rlefile)
    repack_rle_565(rawfile, rlefile, write_565)

if __name__ == '__main__':

    functions = {
                 '--unpack-updata': unpack_updata,
                 '--repack-updata': repack_updata,
                 '--unpack-bootimg': unpack_bootimg,
                 '--unpack-ramdisk': unpack_ramdisk,
                 '--unpack-yaffs': unpack_yaffs,
                 '--unpack-yaffs2': unpack_yaffs,
                 '--unpack-yafffs': unpack_yaffs,
                 '--unpack-rle': unpack_rle,
                 '--unpack-565': unpack_565,
                 '--repack-ramdisk': repack_ramdisk,
                 '--repack-bootimg': repack_bootimg,
                 '--repack-rle': repack_rle,
                 '--repack-565': repack_565,
                 '--cpio-list': cpio_list,
                 '--unpack-simg': unpack_simg,
                }

    def usage():
        sys.stderr.write('supported arguments:')
        sys.stderr.write('\n\t')
        sys.stderr.write('\n\t'.join(sorted(functions.keys())))
        sys.stderr.write('\n')
        raise SystemExit(1)

    if len(sys.argv) == 1:
        usage()

    sys.argv.pop(0)
    name = sys.argv[0]
    function = functions.get(name, None)
    sys.argv.pop(0)
    if not function:
        usage()
    function(*sys.argv)

# vim: set sta sw=4 et:
