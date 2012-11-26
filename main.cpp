/*
    Extractor for LARA Firmware Files

    Copyright (C) 2012
    Andreas Schuler <andreas at schulerdev.de>

    This program is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License v2 as published by the Free
    Software Foundation.

    This program is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
    more details.

    You should have received a copy of the GNU General Public License along with
    this program; if not, write to the Free Software Foundation, Inc., 59 Temple
    Place, Suite 330, Boston, MA 02111-1307 USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#define BIGENDIAN 1

#if BIGENDIAN
    #define SWAP32(x) (((x) & 0xff) << 24 | ((x) & 0xff00) << 8 | ((x) & 0xff0000) >> 8 | ((x) >> 24) & 0xff)
    #define SWAP16(x) (((x) & 0xff) << 8 | (x) >> 8 )
#else
    #define SWAP32(x) (x)
    #define SWAP16(x) (x)
#endif

struct parthead
{
    char magic[14];         //LARA partition
    unsigned short mn;
	unsigned int num;
	unsigned int nextpart;  //byteswapped

	char unknown[72];


	char filename[32];
}__attribute__((packed)); 

struct filehead
{
    char magic[13];             //LARA firmware
    unsigned short mn;
    char infostr1[14];
    unsigned short build;
    char edition[64];
    char vendor[16];
    char product[16];

    char unknown[113];

}__attribute__((packed));

#define MODE_NONE               0
#define MODE_INFO               1
#define MODE_EXTRACT            2

void mode_info(char *fw);
void mode_extract(char *fw);
bool read_parthead(FILE *f,struct parthead *ph);
bool read_filehead(FILE *f,struct filehead *fh);
void print_parthead(struct parthead *ph);
void print_filehead(struct filehead *fh);
void write_file(FILE *f,struct filehead *fh,size_t count);

int main(int argc, char *argv[])
{
    char *filename;
    char c;
    char mode=MODE_NONE;

    printf("LARA partition file manager by Andreas Schuler (andreas at schulerdev dot de)\n");

    while((c=getopt(argc,argv,"ie"))!=-1)
    {
        switch(c)
        {
            case 'i':                   //print header infos
                if(mode==MODE_NONE)
                    mode=MODE_INFO;
                else
                {
                    printf("Can't use both options...\n");
                    abort();
                }
                break;
            case 'e':                   //extract all
                if(mode==MODE_NONE)
                    mode=MODE_EXTRACT;
                else
                {
                    printf("Can't use both options...\n");
                    abort();
                }
                break;
            case '?':
                /* if (optopt=='l' || optopt=='o' || optopt=='e')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                fprintf (stderr, "Unknown option character `\\x%x'.\n",optopt);
                */
                return 1;

            default:
                printf("Usage:\nlara -i firmware : print firmware information\nlara -e firmware : extract firmware file\n");
                abort ();
        }
    }

    if(optind<argc)
        filename=argv[optind];

    switch(mode)
    {
        case MODE_INFO:
            mode_info(filename);
            break;
        case MODE_EXTRACT:
            mode_extract(filename);
            break;
        default:
            mode_info(filename);
            break;
    }

}


void mode_info(char *fw)
{
    FILE *f=fopen(fw,"r");

    if(!f)
    {
        printf("cant open !\n");
        exit(1);
    }

    char md5[16];
    if(fread(md5,1,16,f)!=16)
    {
        printf("Can't read md5 sum\n");
        return;
    }


    printf("md5sum:");
    for(int i=0;i<16;i++)
        printf("%0.2x",((unsigned char)(md5[i])));
    printf("\n");

    struct filehead fh;

    if(!read_filehead(f,&fh))
    {
        printf("cant read fileheader");
        return;
    }

    print_filehead(&fh);

    struct parthead ph;

    while(read_parthead(f,&ph))
    {
        int dofs=ftell(f);
        printf("Data offset: %.8x (%u)\n",dofs,dofs);
        print_parthead(&ph);

        if(ph.nextpart)
            fseek(f,ph.nextpart,SEEK_SET);
        else
            break;
    }

    fclose(f);



}

void mode_extract(char *fw)
{
    FILE *f=fopen(fw,"r");

    if(!f)
    {
        printf("cant open !\n");
        exit(1);
    }

    char md5[16];
    if(fread(md5,1,16,f)!=16)
    {
        printf("Can't read md5 sum\n");
        return;
    }


    printf("md5sum:");
    for(int i=0;i<16;i++)
        printf("%0.2x",((unsigned char)(md5[i])));
    printf("\n");

    struct filehead fh;

    if(!read_filehead(f,&fh))
    {
        printf("cant read fileheader");
        return;
    }

    print_filehead(&fh);

    struct parthead ph;

    size_t lastpos=0x180;

    while(read_parthead(f,&ph))
    {
        print_parthead(&ph);

        if(ph.nextpart)
        {
            write_file(f,&fh,ph.nextpart-lastpos-sizeof(parthead));
            fseek(f,ph.nextpart,SEEK_SET);
        }
        else
            break;

        printf("lastpos:%x, length:%x\n",ph.nextpart,ph.nextpart-lastpos);
        lastpos=ph.nextpart;

    }

    fclose(f);

}


bool read_parthead(FILE *f,struct parthead *ph)
{
    if(fread(ph,1,sizeof(struct parthead),f)!=sizeof(struct parthead))
        return false;

    if(memcmp(ph->magic,"LARA partition",14))
        printf("LARA partition:magic value doesn't matches\n");

    ph->num=SWAP32(ph->num);
    ph->nextpart=SWAP32(ph->nextpart);
    ph->mn=SWAP16(ph->mn);

    return true;
}

void print_parthead(struct parthead *ph)
{
    printf("Magic Value:           %s\n",ph->magic);
    printf("Magic Number:          %u\n",ph->mn);
    printf("Partition Number:      %u\n",ph->num);
    printf("Next Partition Offset: 0x%x\n",ph->nextpart);
    printf("Filename:              %s\n",ph->filename);

    printf("Unknown Bytes:\n");
    int i=0;
    while(i<72)
    {
        printf("%.2x",((unsigned char)(ph->unknown[i])));

        if(((i+1)%16)==0)
            printf("\n");

        i++;
    }

    printf("\n\n");

}

bool read_filehead(FILE *f,struct filehead *fh)
{
    if(fread(fh,1,sizeof(struct filehead),f)!=sizeof(struct filehead))
        return false;

    if(memcmp(fh->magic,"LARA firmware",13))
    {
        printf("LARA firmware:magic value doesn't matches\n");
        return false;
    }

    fh->mn=SWAP16(fh->mn);
    fh->build=SWAP16(fh->build);

    return true;
}

void print_filehead(struct filehead *fh)
{
    printf("Magic Value:           %s\n",fh->magic);
    printf("Magic Number:          %u\n",fh->mn);
    printf("infostr1:              %s\n",fh->infostr1);
    printf("build:                 %u\n",fh->build);
    printf("edition:               %s\n",fh->edition);
    printf("vendor:                %s\n",fh->vendor);
    printf("product:               %s\n",fh->product);

    printf("Unknown Bytes:\n");
    int i=0;
    while(i<112)
    {
        printf("%.2x",((unsigned char)(fh->unknown[i])));

        if(((i+1)%16)==0)
            printf("\n");

        i++;
    }

    printf("\n\n");
}

char partname[]="partname_0";

void write_file( FILE *f, struct filehead *fh,size_t count)
{
    FILE *outf=fopen(partname,"w+");

    printf("writing file :%s\n",partname);
    partname[9]++;

    char buf[512];
    size_t rlen=0,wlen=0;

    while(!feof(f))
    {
        if(count<=0)
            break;

        rlen=(count<512)?count:512;
        wlen=fread(buf,1,rlen,f);
        fwrite(buf,1,wlen,outf);
        count-=wlen;
    }

    fclose(outf);

}
