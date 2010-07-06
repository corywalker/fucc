#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifdef __BIG_ENDIAN__
#error Implement FLIPLE
#else
#define FLIPLE(x)
#endif

#define OBJECT_IDENTIFIER 0x6
#define OCTET 0x4
#define CERT_POLICY "\x55\x1D\x20"

#define v_printf(format, ...) if(Verbose) printf(format, ## __VA_ARGS__)

typedef struct Tag
{
	struct Tag* parent;
	uint8_t type;
	int depth;
	int constructed;
	int size;
	int sizeBytes;
	uint8_t* sizePtr;
	uint8_t* contentPtr;
	struct Tag* next;
	struct Tag* prev;
} Tag;

int Verbose;

static inline int isString(int type)
{
	if(type == 0xC)
		return 1;

	if(type == 0x12)
		return 1;

	if(type == 0x13)
		return 1;

	if(type == 0x14)
		return 1;

	if(type == 0x15)
		return 1;

	if(type == 0x16)
		return 1;

	if(type == 0x19)
		return 1;

	if(type == 0x1A)
		return 1;

	if(type == 0x1B)
		return 1;

	if(type == 0x1C)
		return 1;

	if(type == 0x1D)
		return 1;

	return 0;
}

Tag* parse(Tag** list, Tag* parent, int depth, uint8_t* data, size_t dataLen)
{
	int force_constructed = 0;
	uint8_t* cur = data;
	Tag* first = NULL;
	Tag* last = *list;
	while(cur < (data + dataLen))
	{
		Tag* newTag = (Tag*) malloc(sizeof(Tag));
		newTag->type = *cur;
		++cur;

		newTag->depth = depth;

		newTag->sizePtr = cur;
		if((*cur & 0x80) != 0)
		{
			newTag->sizeBytes = 0x7f & *cur;
			newTag->size = 0;
			++cur;

			int bytes;
			for(bytes = 1; bytes <= newTag->sizeBytes; ++bytes)
			{
				newTag->size += *cur << ((newTag->sizeBytes - bytes) * 8);
				++cur;
			}
		} else
		{
			newTag->sizeBytes = 0;
			newTag->size = *cur;
			++cur;
		}

		newTag->contentPtr = cur;
		cur += newTag->size;

		if(force_constructed)
			newTag->constructed = 1;
		else
			newTag->constructed = (newTag->type & 0x20) != 0 ? 1 : 0;

		newTag->next = NULL;
		newTag->prev = last;
		newTag->parent = parent;

		if(last != NULL)
			last->next = newTag;

		if(first == NULL)
			first = newTag;

		last = newTag;

		int i;
		for(i = 0; i < depth; ++i)
		{
			v_printf("  ");
		}

		if(newTag->constructed)
		{
			v_printf("Tag (constructed): %02x = %d\n", newTag->type, newTag->size);
			last = parse(&last, newTag, depth + 1, newTag->contentPtr, newTag->size);
		} else if(isString(newTag->type))
		{
			v_printf("Tag %02x = %d: ", newTag->type, newTag->size);
			for(i = 0; i < newTag->size; ++i)
			{
				v_printf("%c", newTag->contentPtr[i]);
			}
			v_printf("\n");
		} else
		{
			v_printf("Tag %02x = %d\n", newTag->type, newTag->size);
		}

		// special exception for the policy tag, which contain some truncateable info.
		if(newTag->type == OBJECT_IDENTIFIER && newTag->size == 3 && memcmp(newTag->contentPtr, CERT_POLICY, sizeof(CERT_POLICY) - 1) == 0)
		{
			force_constructed = 1;
		}
	}

	if(*list == NULL)
		*list = first;

	return last;
}

int writeTags(Tag* list, FILE* f)
{
	int lastBitstring = 0;
	while(list != NULL)
	{
		fwrite(&list->type, 1, 1, f);
		fwrite(list->sizePtr, 1, list->sizeBytes + 1, f);
		if(!list->constructed)
		{
			if(list->type == 0x3)
				lastBitstring = ftell(f) + 1;

			fwrite(list->contentPtr, 1, list->size, f);
		}

		list = list->next;
	}
	
	return lastBitstring;
}

void expand(Tag* tag, int expandSize, uint32_t fill)
{
	uint8_t* newContents = (uint8_t*) malloc(expandSize + tag->size);

	int off = 0;
	int i;

	if(tag->type == 0x3)
		off = 1;

	for(i = 0; i < (expandSize + tag->size); ++i)
	{
		newContents[i] = ((uint8_t*)&fill)[(i - off) % 4];
	}

	memcpy(newContents, tag->contentPtr, tag->size);
	tag->contentPtr = newContents;

	for(; tag != NULL; tag = tag->parent)
	{
		v_printf("Tag %02x: %d -> %d\n", tag->type, tag->size, tag->size + expandSize);
		tag->size += expandSize;
		if(tag->sizeBytes == 0 && tag->size <= 0x7f)
			*tag->sizePtr = tag->size;
		else if(tag->sizeBytes > 0 && (1 << (tag->sizeBytes * 8)) > tag->size)
		{
			uint8_t* curByte;
			int remaining = tag->size;
			for(curByte = tag->sizePtr + tag->sizeBytes; curByte > tag->sizePtr; --curByte)
			{
				*curByte = remaining & 0xff;
				remaining >>= 8;
			}
		}
		else
		{
			uint8_t* curByte;
			int remaining = tag->size;
			tag->sizePtr = (uint8_t*) malloc(sizeof(uint32_t) + 1);
			for(curByte = tag->sizePtr + 4; curByte > tag->sizePtr; --curByte)
			{
				*curByte = remaining & 0xff;
				remaining >>= 8;
				if(remaining == 0)
				{
					int bytes = 5 - (curByte - tag->sizePtr);
					*tag->sizePtr = 0x80 | bytes;
					memmove(tag->sizePtr + 1, curByte, bytes);
					expandSize += bytes - tag->sizeBytes;
					tag->sizeBytes = bytes;
					break;
				}
			}
		}
	}
}

int shrink(Tag* tag, int shrinkSize)
{
	Tag* orig = tag;
	int shrinkExtra = 0;

	if(tag->size < (shrinkSize + 1))
	{
		shrinkExtra = shrinkSize - (tag->size - 1);
		shrinkSize = tag->size - 1;
	}

	int savings = shrinkSize;

	for(tag = orig; tag != NULL; tag = tag->parent)
	{
		v_printf("Tag %02x: %d -> %d\n", tag->type, tag->size, tag->size - savings);
		tag->size -= savings;
		if(tag->sizeBytes == 0)
			*tag->sizePtr = tag->size;
		else
		{
			uint8_t* curByte;
			int remaining = tag->size;
			for(curByte = tag->sizePtr + tag->sizeBytes; curByte > tag->sizePtr; --curByte)
			{
				*curByte = remaining & 0xff;
				remaining >>= 8;
			}
		}

		if(shrinkExtra == 0)
			continue;

		if(tag->sizePtr > 0)
		{
			uint8_t* curByte;
			for(curByte = tag->sizePtr + 1; curByte <= (tag->sizePtr + tag->sizeBytes); ++curByte)
			{
				if(*curByte == 0 && tag->sizeBytes > 1)
				{
					v_printf("Compact tag size %p (%02x): %d -> %d\n", tag, tag->type, tag->sizeBytes, tag->sizeBytes - 1);
					--tag->sizeBytes;
					++tag->sizePtr;
					--shrinkExtra;
					*tag->sizePtr = 0x80 | tag->sizeBytes;
					++savings;

					if(shrinkExtra == 0)
						continue;
				}
				else
					break;
			}

			if(tag->sizeBytes == 1 && tag->size <= 0x7f)
			{
				v_printf("Compact tag size to single byte %p (%02x): %d -> %d\n", tag, tag->type, tag->sizeBytes, tag->sizeBytes - 1);
				tag->sizeBytes = 0;
				*tag->sizePtr = tag->size;
				--shrinkExtra;
				++savings;
			}
		}
	}

	return shrinkExtra;
}

int main(int argc, char* argv[])
{
	Verbose = 1;

	if(argc < 4)
	{
		printf("Firmware Upload Certificate Corrupter 0.1\n");
		printf("This spaghetti code is brought to you by planetbeing.\n\n");
		printf("%s <cert> <out> <size> [fill] [out-cert]\n", argv[0]);
		return 0;
	}

	uint32_t fill;

	if(argc >= 5)
	{
		long long lFill = strtoll(argv[4], NULL, 0);
		fill = lFill;
		FLIPLE(fill);
	}

	FILE* f;
	FILE* out;
	FILE* outc = NULL;

	if((f = fopen(argv[1], "rb")) == NULL)
	{
		perror("fopen");
		return 1;
	}

	if((out = fopen(argv[2], "wb")) == NULL)
	{
		perror("fopen");
		return 1;
	}

	if(argc >= 6 && (outc = fopen(argv[5], "wb")) == NULL)
	{
		perror("fopen");
		return 1;
	}

	int shrinkSize = strtol(argv[3], NULL, 0);

	uint32_t fileLen;
	fseek(f, 0, SEEK_END);
	fileLen = ftell(f);
	fseek(f, 0, SEEK_SET);
	uint8_t* input = (uint8_t*) malloc(fileLen);
	fread(input, 1, fileLen, f);
	fclose(f);

	uint32_t footerCertLen = *(uint32_t*)(input + 0x18);
	FLIPLE(footerCertLen);
	uint8_t* cert = input + fileLen - footerCertLen;

	Tag* list = NULL;

	parse(&list, NULL, 0, cert, footerCertLen);

	Tag* cur;
	Tag* lastBitString = NULL;
	for(cur = list; cur != NULL; cur = cur->next)
	{
		if(cur->type == 0x3 && cur->depth == 1)
			lastBitString = cur;
	}

	expand(lastBitString, shrinkSize, fill);
	int shrinkLeft = shrinkSize;

	for(cur = list; cur != NULL; cur = cur->next)
	{
		if(isString(cur->type))
			shrinkLeft = shrink(cur, shrinkLeft);

		if(cur->type == 0x3 && cur->depth == 1 && cur != lastBitString)
			shrinkLeft = shrink(cur, shrinkLeft);
	}

	fwrite(input, 1, fileLen, out);

	fseek(out, fileLen - footerCertLen, SEEK_SET);
	int bitstringOffset = writeTags(list, out);
	printf("Size difference: %d\tFooter sig at offset 0x%x\n", (int)(ftell(out) - fileLen), bitstringOffset);
	fclose(out);

	if(outc)
	{
		writeTags(list, outc);
		fclose(outc);
	}

	Tag* next = list;
	while(next)
	{
		cur = next;

		// detect if we dynamically allocated it
		if(cur->sizePtr < input || cur->sizePtr > (input + fileLen))
			free(cur->sizePtr);

		if(cur->contentPtr < input || cur->contentPtr > (input + fileLen))
			free(cur->contentPtr);

		next = cur->next;
		free(cur);
	}

	return 0;
}

