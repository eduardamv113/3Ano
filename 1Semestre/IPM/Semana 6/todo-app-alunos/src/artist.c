// artist.c
#include "artist.h"
#include <string.h>
#include <stdio.h>

int create_and_store_artist(char **artist_data, void *artist_catalog) {
    if (!validate_artist(artist_data, 6)) {
        return 1;
    }

    Artist* artist = (Artist*)malloc(sizeof(Artist));
    if (!artist) return 1;

    set_artist_id(artist, artist_data[0]);
    set_artist_name(artist, artist_data[1]);
    set_artist_description(artist, artist_data[2]);
    set_artist_recipe_per_stream(artist, atof(artist_data[3]));  // Conversão para float
    set_artist_id_constituent(artist, artist_data[4]);
    set_artist_country(artist, artist_data[5]);
    set_artist_discography_duration(artist, 0); // Inicialização a 0

    if(strcmp(artist_data[6], "individual") == 0) {
        artist->type = INDIVIDUAL;
    }
    else {
        artist->type = GROUP;
    }

    insert_artist((CatalogArtist*)artist_catalog, artist);

    return 0;
}

void free_artist(void *artist_void) {
    Artist* artist = (Artist*)artist_void;
    if (!artist) return;
    free(artist->id);
    free(artist->name);
    free(artist->description);
    free(artist->id_constituent);
    free(artist->country);
    free(artist);
}


char* get_artist_id(Artist* artist) {
    return strdup(artist->id);
}

void set_artist_id(Artist* artist, char* id) {
    artist->id = strdup(id);
}

char* get_artist_name(Artist* artist) {
    return strdup(artist->name);
}

void set_artist_name(Artist* artist, char* name) {
    artist->name = strdup(name);
}

char* get_artist_description(Artist* artist) {
    return strdup(artist->description);
}

void set_artist_description(Artist* artist, char* description) {
    artist->description = strdup(description);
}

float get_artist_recipe_per_stream(Artist* artist) {
    return artist->recipe_per_stream;
}

void set_artist_recipe_per_stream(Artist* artist, float recipe_per_stream) {
    artist->recipe_per_stream = recipe_per_stream;
}

char* get_artist_id_constituent(Artist* artist) {
    return strdup(artist->id_constituent);
}

void set_artist_id_constituent(Artist* artist, char* id_constituent) {
    artist->id_constituent = strdup(id_constituent);
}

char* get_artist_country(Artist* artist) {
    return strdup(artist->country);
}

void set_artist_country(Artist* artist, char* country) {
    artist->country = strdup(country);
}

Type get_artist_type(Artist* artist) {
    return artist->type;
}

void set_artist_type(Artist* artist, Type type) {
    artist->type = type;
}

int get_artist_discography_duration(Artist* artist) {
    return artist->discography_duration;
}

void set_artist_discography_duration(Artist* artist, int discography_duration) {
    artist->discography_duration = discography_duration;
}
