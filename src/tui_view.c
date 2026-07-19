#include "tui_view.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

const char *
tui_state_name(enum capture_transaction_state state)
{
	switch (state) {
	case CAPTURE_REQUEST:
		return "request";
	case CAPTURE_WAITING_RESPONSE:
		return "aguardando";
	case CAPTURE_RESPONSE:
		return "response";
	case CAPTURE_COMPLETE:
		return "completa";
	case CAPTURE_INTERRUPTED:
		return "interrompida";
	case CAPTURE_ERROR:
		return "erro";
	}
	return "desconhecido";
}

const char *
tui_verify_name(int verified)
{
	switch (verified) {
	case 1:
		return "verificado";
	case 0:
		return "falhou";
	case -1:
		return "desativado";
	case -2:
		return "n/a";
	default:
		return "desconhecido";
	}
}

/* Escolhe unidades binarias para manter numeros grandes compactos na TUI. */
void
tui_format_bytes(uint64_t bytes, char *output, size_t output_size)
{
	static const char *units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double value;
	size_t unit;

	if (output == NULL || output_size == 0)
		return;
	value = (double)bytes;
	unit = 0;
	while (value >= 1024.0 && unit + 1 <
	    sizeof(units) / sizeof(units[0])) {
		value /= 1024.0;
		unit++;
	}
	if (unit == 0)
		(void)snprintf(output, output_size, "%llu %s",
		    (unsigned long long)bytes, units[unit]);
	else
		(void)snprintf(output, output_size, "%.1f %s", value,
		    units[unit]);
}

void
tui_format_body_summary(const struct capture_message_view *message,
	char *output, size_t output_size)
{
	char stored[32], total[32];

	if (output == NULL || output_size == 0)
		return;
	if (message == NULL) {
		output[0] = '\0';
		return;
	}
	tui_format_bytes(message->body_len, stored, sizeof(stored));
	tui_format_bytes(message->body_total, total, sizeof(total));
	if (message->body_truncated) {
		(void)snprintf(output, output_size,
		    "body: %s de %s guardados%s", stored, total,
		    message->binary ? ", binario" : "");
	} else {
		(void)snprintf(output, output_size, "body: %s%s", total,
		    message->binary ? ", binario" : "");
	}
}

void
tui_format_destination(const struct capture_transaction_summary *transaction,
	char *output, size_t output_size)
{
	if (output == NULL || output_size == 0)
		return;
	if (transaction == NULL) {
		output[0] = '\0';
		return;
	}
	if (strncasecmp(transaction->target, "http://", 7) == 0 ||
	    strncasecmp(transaction->target, "https://", 8) == 0 ||
	    transaction->host[0] == '\0') {
		(void)snprintf(output, output_size, "%s", transaction->target);
	} else {
		(void)snprintf(output, output_size, "%s%s%s", transaction->host,
		    transaction->target[0] == '/' ? "" : "/",
		    transaction->target);
	}
}

/*
 * O ID, e nao o indice, e a ancora da selecao. A lista pode crescer ou perder
 * registros antigos entre dois frames sem fazer a selecao pular de item.
 */
size_t
tui_selection_sync(const struct capture_transaction_summary *transactions,
	size_t count, uint64_t *selected_id)
{
	size_t i;

	if (selected_id == NULL || transactions == NULL || count == 0) {
		if (selected_id != NULL)
			*selected_id = 0;
		return 0;
	}
	for (i = 0; i < count; i++) {
		if (transactions[i].id == *selected_id)
			return i;
	}
	*selected_id = transactions[count - 1].id;
	return count - 1;
}

size_t
tui_selection_move(const struct capture_transaction_summary *transactions,
	size_t count, uint64_t *selected_id, int delta)
{
	size_t index, movement;

	index = tui_selection_sync(transactions, count, selected_id);
	if (count == 0)
		return 0;
	if (delta < 0) {
		movement = (size_t)(-(long long)delta);
		index = movement > index ? 0 : index - movement;
	} else {
		movement = (size_t)delta;
		index = movement >= count - index ? count - 1 : index + movement;
	}
	*selected_id = transactions[index].id;
	return index;
}

/*
 * Produz uma linha no formato classico: offset, 16 bytes hexadecimais e ASCII.
 * O retorno informa quantos bytes foram consumidos para montar a proxima linha.
 */
size_t
tui_hexdump_line(const unsigned char *data, size_t length, size_t offset,
	char *output, size_t output_size)
{
	char ascii[17];
	size_t available, i, pos;

	if (output == NULL || output_size == 0)
		return 0;
	output[0] = '\0';
	if (data == NULL || offset >= length)
		return 0;
	available = length - offset;
	if (available > 16)
		available = 16;
	pos = (size_t)snprintf(output, output_size, "%08zx  ", offset);
	for (i = 0; i < 16 && pos < output_size; i++) {
		if (i < available)
			pos += (size_t)snprintf(output + pos, output_size - pos,
			    "%02x ", data[offset + i]);
		else
			pos += (size_t)snprintf(output + pos, output_size - pos,
			    "   ");
		ascii[i] = i < available && isprint(data[offset + i]) ?
		    (char)data[offset + i] : '.';
	}
	ascii[16] = '\0';
	if (pos < output_size)
		(void)snprintf(output + pos, output_size - pos, " |%.*s|",
		    (int)available, ascii);
	return available;
}
