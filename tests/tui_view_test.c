#include "tui_view.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: falhou: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

static void
test_selection_survives_refresh(void)
{
	struct capture_transaction_summary transactions[3];
	uint64_t selected;

	memset(transactions, 0, sizeof(transactions));
	transactions[0].id = 10;
	transactions[1].id = 20;
	transactions[2].id = 30;
	selected = 0;
	CHECK(tui_selection_sync(transactions, 3, &selected) == 2);
	CHECK(selected == 30);
	CHECK(tui_selection_move(transactions, 3, &selected, -1) == 1);
	CHECK(selected == 20);
	CHECK(tui_selection_move(transactions, 3, &selected, -20) == 0);
	CHECK(selected == 10);
	CHECK(tui_selection_move(transactions, 3, &selected, 20) == 2);
	CHECK(selected == 30);

	/* Depois de eviction, um ID ausente seleciona a entrada mais recente. */
	transactions[0].id = 40;
	transactions[1].id = 50;
	CHECK(tui_selection_sync(transactions, 2, &selected) == 1);
	CHECK(selected == 50);
	CHECK(tui_selection_sync(NULL, 0, &selected) == 0);
	CHECK(selected == 0);
}

static void
test_body_formatting(void)
{
	struct capture_message_view message;
	struct capture_transaction_summary transaction;
	char output[128];

	memset(&message, 0, sizeof(message));
	message.body_len = 1024;
	message.body_total = 4096;
	message.body_truncated = 1;
	message.binary = 1;
	tui_format_body_summary(&message, output, sizeof(output));
	CHECK(strstr(output, "1.0 KiB de 4.0 KiB") != NULL);
	CHECK(strstr(output, "binario") != NULL);
	CHECK(strcmp(tui_state_name(CAPTURE_INTERRUPTED), "interrompida") == 0);
	CHECK(strcmp(tui_verify_name(-1), "desativado") == 0);
	memset(&transaction, 0, sizeof(transaction));
	(void)snprintf(transaction.host, sizeof(transaction.host),
	    "example.test");
	(void)snprintf(transaction.target, sizeof(transaction.target), "/api");
	tui_format_destination(&transaction, output, sizeof(output));
	CHECK(strcmp(output, "example.test/api") == 0);
	(void)snprintf(transaction.target, sizeof(transaction.target),
	    "http://example.test/api");
	tui_format_destination(&transaction, output, sizeof(output));
	CHECK(strcmp(output, "http://example.test/api") == 0);
}

static void
test_hexdump(void)
{
	static const unsigned char data[] = { 'A', 0, 'B', 0xff };
	char output[128];

	CHECK(tui_hexdump_line(data, sizeof(data), 0, output,
	    sizeof(output)) == sizeof(data));
	CHECK(strstr(output, "41 00 42 ff") != NULL);
	CHECK(strstr(output, "|A.B.|") != NULL);
	CHECK(tui_hexdump_line(data, sizeof(data), sizeof(data), output,
	    sizeof(output)) == 0);
}

int
main(void)
{
	test_selection_survives_refresh();
	test_body_formatting();
	test_hexdump();
	if (failures != 0)
		return 1;
	puts("tui_view_test: ok");
	return 0;
}
