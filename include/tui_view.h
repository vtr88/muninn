#ifndef TUI_VIEW_H
#define TUI_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "capture.h"

/*
 * Estas funcoes nao conhecem ncurses. Elas concentram decisoes da interface
 * que podem ser exercitadas por testes comuns e reutilizadas pelo desenho.
 */
const char *tui_state_name(enum capture_transaction_state);
const char *tui_verify_name(int);
void tui_format_bytes(uint64_t, char *, size_t);
void tui_format_body_summary(const struct capture_message_view *, char *,
    size_t);
void tui_format_destination(const struct capture_transaction_summary *, char *,
    size_t);

size_t tui_selection_sync(const struct capture_transaction_summary *, size_t,
    uint64_t *);
size_t tui_selection_move(const struct capture_transaction_summary *, size_t,
    uint64_t *, int);

size_t tui_hexdump_line(const unsigned char *, size_t, size_t, char *, size_t);

#endif
