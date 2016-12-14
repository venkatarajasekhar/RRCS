#include "destor.h"

void  dedup_mark_send(int fd,MemIndex* memdex,Recipe *rp,char * buf){
    FingerChunk *fc=NULL;
    fc=rp->first;
    int i=0;
    memset(buf,0,SOCKET_BUF_SIZE);
    while(fc){

        if(index_lookup(memdex,fc->fingerprint)){
            fc->existed=1;
            buf[i++]='1';
        }
        else
            buf[i++]='0'; 
        if(i>=SOCKET_BUF_SIZE){
            printf("%s %d bigBuf is not enough\n",__FILE__,__LINE__);
            bnet_send(fd,buf,i);    
            memset(buf,0,SOCKET_BUF_SIZE);
            i=0;
        }
        fc=fc->next;
    }
    if(i>0){
        bnet_send(fd,buf,i);    
    }
    bnet_signal(fd,FINGER_RESP_END);
}
void backup_dedup(int fd,char *msg){
    JCR *jcr=NULL;
    char fileset[256]={0};
    char *buf=(char *)calloc(1,SOCKET_BUF_SIZE+21);
    int len;
    int type;
    int index;
    Recipe *rp=NULL;
    FingerChunk *fc=NULL;
    char *p=NULL;
    Chunk *chunk=NULL;
    
    char *flag_real = malloc(sizeof(int));
    sprintf(flag_real, "%d", 1);                            // the flag of the non-duplicate chunk
    
    container_vol_init();
    jobcount_init();
    jcr=jcr_new();

    jcr->dataSocket=fd;
    jcr->memIndex=index_init();
    jcr->container=container_new();
    if(sscanf(msg,backup_cmd,fileset)!=1){ 
        goto FAIL;
    }
    jcr->jobv=jobv_new(fileset);
    jcr->nJobId=jcr->jobv->nJobId;
    
    printf("===========backup start==============\n");
    printf("%s,%d pathname:%s \n", __FILE__,__LINE__,fileset);

    TIMER_DECLARE(gstart,gend);
    TIMER_DECLARE(sstart,ssend);
    TIMER_DECLARE(wstart,wend);
    
    TIMER_START(gstart);
    while(bnet_recv(jcr->dataSocket,buf,&len)!=ERROR){
        if(len==STREAM_END){
            printf("%s %d backup is over\n",__FILE__,__LINE__);
            break;
        }
        jcr->nRecvSize+=len;

        if(sscanf(buf,"%d %d",&index,&type)!=2) 
            goto FAIL;    
        switch(type){
            case FILE_NAME:
                while(bnet_recv(jcr->dataSocket,buf,&len)>0){
                    jcr->nRecvSize+=len;
                    rp=recipe_new();
                    memcpy(rp->filename,buf,len);
                    rp->fileindex=index;    
                }
                break;
            case FILE_FINGERPRINT:
                while(bnet_recv(jcr->dataSocket,buf,&len)>0){
                    jcr->nRecvSize+=len;
                    p=buf;
                    while(p-buf<len){
                        fc=fingerchunk_new(p,0);
                        recipe_append_fingerchunk(rp,fc);
                        p+=sizeof(Fingerprint);
                    }
                }
                TIMER_START(sstart);
                dedup_mark_send(fd,jcr->memIndex,rp,buf);
                
                TIMER_END(ssend);
                TIMER_DIFF(jcr->searchTime,sstart,ssend);
                break;
            case FILE_DATA:
                while(bnet_recv(jcr->dataSocket,buf,&len)>0){ 				//	format: fingerprint-flag-data..
                    jcr->nRecvSize+=len;
                    char* flag = malloc(sizeof(int));
                    memcpy(flag, buf+sizeof(Fingerprint), sizeof(int));

                    if(strcmp(flag, flag_real) == 0){                   	// check the flag of the non-duplicate/redundant chunk
                        chunk=chunk_new(buf,buf+sizeof(Fingerprint)+sizeof(int),len-sizeof(Fingerprint)-sizeof(int));
                        TIMER_START(wstart);
                        while(write_chunk(jcr->container, chunk)==false){
                            write_container(jcr->container);
                            index_insert(jcr->memIndex,jcr->container);
                            container_destroy(jcr->container);
                            jcr->container=container_new();
                        }
                        TIMER_END(wend);
                        TIMER_DIFF(jcr->writeDataTime,wstart,wend);
                        jcr->nDedupChunkCount++;
                        jcr->nDedupSize+=chunk->length;
                        chunk_free(chunk);
                    }
                }

                jcr->nChunkCount+=rp->chunknum;
                jcr->nFileCount++;
                if(G_VERBOSE)
                    printf("receive file %s OK, total: %d\n",rp->filename,jcr->nFileCount);
                jobv_insert_recipe(jcr->jobv, rp);
                recipe_free(rp);
                rp=recipe_new();
                break;
            default:
                printf("%s %d wrong\n",__FILE__,__LINE__);
                break;
        }
    }
    
FAIL:
    TIMER_END(gend);
    TIMER_DIFF(jcr->recvTime,gstart,gend);
    
    TIMER_START(wstart);
    if(jcr->container){

        if(jcr->container->data_size>0){
            write_container(jcr->container);
            index_insert(jcr->memIndex,jcr->container);
        }
        container_destroy(jcr->container);
    }

    bnet_send(fd,"OK",2); 
    
    TIMER_END(wend);
    TIMER_DIFF(jcr->writeDataTime,wstart,wend);
    printf("============back over===============\n");
    printf("total time:%.4f   throughput:%.4f MB/s\n",jcr->recvTime,jcr->nRecvSize*1.0/jcr->recvTime/1036288.0);
    printf("search  time:%.4f \n ",jcr->searchTime);
    printf("writedata time:%.4f throughput:%.4f MB/s\n",jcr->writeDataTime,jcr->nDedupSize*1.0/jcr->writeDataTime/1036288.0);
    printf("old chunk count:%d, deduped chunk count:%d\n",jcr->nChunkCount,jcr->nDedupChunkCount);
    
    if(rp){
        recipe_free(rp);
    }
    
    jobv_destroy(jcr->jobv);
    jcr_free(jcr);
    container_vol_destroy();
    jobcount_close();
    index_destroy(jcr->memIndex);
}
