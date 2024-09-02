package attack

import (
	"testing"

	"github.com/SecurityBrewery/catalyst-analysis/plugin"
	"github.com/SecurityBrewery/catalyst-analysis/plugin/plugintest"
)

func TestAttack(t *testing.T) {
	t.Parallel()

	plugintest.TestPlugin(t, New())
}

func TestTechnique(t *testing.T) {
	t.Parallel()

	plugintest.TestResourceType(t, plugintest.ResourceTypeTest{
		ResourceType:        Technique,
		MatchingExamples:    []string{"T1001", "T1001.001", "T1001.002"},
		NonMatchingExamples: []string{"T1", "T100", "T2001"},
		Enrichments: map[string]*plugin.Resource{
			"T1001": {
				ID:          "T1001",
				Icon:        "Shield",
				Type:        "technique",
				Name:        "T1001 Data Obfuscation",
				Description: "Adversaries may obfuscate command and control traffic to make it more difficult to detect.(Citation: Bitdefender FunnyDream Campaign November 2020) Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.",
				Attributes:  []plugin.Attribute{},
				URL:         "https://attack.mitre.org/techniques/T1001",
			},
		},
		Suggestions: map[string][]*plugin.Resource{
			"Masquerading": {{
				ID:          "T1036",
				Icon:        "Shield",
				Type:        "technique",
				Name:        "T1036 Masquerading",
				Description: "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.\n\nRenaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site)",
				Attributes:  []plugin.Attribute{},
				URL:         "https://attack.mitre.org/techniques/T1036",
			}},
		},
	})
}

func TestTactic(t *testing.T) {
	t.Parallel()

	plugintest.TestResourceType(t, plugintest.ResourceTypeTest{
		ResourceType:        Tactic,
		MatchingExamples:    []string{"TA0001"},
		NonMatchingExamples: []string{"TA0000"},
		Enrichments: map[string]*plugin.Resource{
			"TA0010": {
				ID:          "TA0010",
				Icon:        "Shield",
				Type:        "tactic",
				Name:        "TA0010 Exfiltration",
				Description: "The adversary is trying to steal data.\n\nExfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.",
				Attributes:  []plugin.Attribute{},
				URL:         "https://attack.mitre.org/tactics/TA0010",
			},
		},
	})
}
