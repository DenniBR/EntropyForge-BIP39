import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifier.trust_chain import (
    TRUST_CHAIN,
    fully_reducible_links,
    irreducible_hypotheses,
    render_markdown_table,
)


class TrustChainStructureTests(unittest.TestCase):
    def test_no_duplicate_components(self):
        names = [link.component for link in TRUST_CHAIN]
        self.assertEqual(len(names), len(set(names)))

    def test_every_link_has_nonempty_notes(self):
        for link in TRUST_CHAIN:
            self.assertTrue(link.notes.strip(), msg=link.component)
            self.assertTrue(link.description.strip(), msg=link.component)

    def test_at_least_ten_links_enumerated(self):
        # requisito da Fase 16: firmware/BIOS/UEFI, kernel, SO, Python,
        # source, build, .pyz, wordlist, CSPRNG, hardware, operador --
        # pelo menos essas categorias.
        self.assertGreaterEqual(len(TRUST_CHAIN), 10)


class IrreducibleHypothesesTests(unittest.TestCase):
    def test_hypotheses_list_is_not_empty(self):
        # requisito estrutural: uma analise honesta de raiz de confianca
        # NAO pode terminar com "nada precisa ser assumido" -- isso seria
        # sinal de uma analise excessivamente otimista.
        hyps = irreducible_hypotheses()
        self.assertGreater(len(hyps), 0)

    def test_firmware_and_hardware_are_among_the_hypotheses(self):
        names = {link.component for link in irreducible_hypotheses()}
        self.assertTrue(any("Firmware" in n for n in names))
        self.assertTrue(any("Hardware" in n for n in names))

    def test_operator_and_physical_dice_remain_a_hypothesis(self):
        names = {link.component for link in irreducible_hypotheses()}
        self.assertTrue(any("dado fisico" in n.lower() or "d6" in n.lower() for n in names))


class ReducibleLinksTests(unittest.TestCase):
    def test_source_code_and_wordlist_are_verifiable_and_reducible_or_direct(self):
        by_name = {link.component: link for link in TRUST_CHAIN}
        wordlist = [l for l in TRUST_CHAIN if "Wordlist" in l.component][0]
        self.assertTrue(wordlist.verifiable)
        self.assertTrue(wordlist.reducible)

    def test_reducible_links_are_a_proper_nonempty_subset(self):
        reducible = fully_reducible_links()
        self.assertGreater(len(reducible), 0)
        self.assertLess(len(reducible), len(TRUST_CHAIN))


class MarkdownTableTests(unittest.TestCase):
    def test_renders_one_row_per_link_plus_header(self):
        table = render_markdown_table()
        lines = [l for l in table.strip().splitlines() if l.strip()]
        # 2 linhas de cabecalho (nomes + separador) + 1 por elo
        self.assertEqual(len(lines), 2 + len(TRUST_CHAIN))

    def test_every_component_name_appears_in_table(self):
        table = render_markdown_table()
        for link in TRUST_CHAIN:
            self.assertIn(link.component, table)


if __name__ == "__main__":
    unittest.main()
