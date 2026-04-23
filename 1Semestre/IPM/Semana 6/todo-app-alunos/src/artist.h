// artist.h
#ifndef ARTIST_H
#define ARTIST_H

#include <stdlib.h>

typedef enum { INDIVIDUAL, GROUP } Type;

typedef struct Artist {
    char *id;
    char *name;
    char *description;
    float recipe_per_stream;
    char *id_constituent;
    char *country;
    Type type;
    int discography_duration;
} Artist;

// Forward declarations for external catalog
typedef struct CatalogArtist CatalogArtist;

// Prototypes
int create_and_store_artist(char **artist_data, void *artist_catalog);
void free_artist(void *artist_void);

char* get_artist_id(Artist* artist);
void set_artist_id(Artist* artist, char* id);
char* get_artist_name(Artist* artist);
void set_artist_name(Artist* artist, char* name);
char* get_artist_description(Artist* artist);
void set_artist_description(Artist* artist, char* description);
float get_artist_recipe_per_stream(Artist* artist);
void set_artist_recipe_per_stream(Artist* artist, float recipe_per_stream);
char* get_artist_id_constituent(Artist* artist);
void set_artist_id_constituent(Artist* artist, char* id_constituent);
char* get_artist_country(Artist* artist);
void set_artist_country(Artist* artist, char* country);
Type get_artist_type(Artist* artist);
void set_artist_type(Artist* artist, Type type);
int get_artist_discography_duration(Artist* artist);
void set_artist_discography_duration(Artist* artist, int discography_duration);

// External functions expected to be provided elsewhere
int validate_artist(char **artist_data, int expected_fields);
void insert_artist(CatalogArtist *catalog, Artist *artist);

#endif // ARTIST_H
