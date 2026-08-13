package com.maciejgojny.desync;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.maciejgojny.desync.menu.DesyncContextMenu;
import com.maciejgojny.desync.replay.DesyncReplayer;
import com.maciejgojny.desync.ui.CortexTab;

public class DesyncExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Desync Hypothesis Scanner - Maciej Gojny");

        DesyncReplayer replayer = new DesyncReplayer();

        // Each entry-point owns its own HypothesisGenerator: the generator carries
        // mutable per-scan configuration, so sharing one instance across the tab and
        // the context menu would let concurrent scans race on its fields.
        api.userInterface().registerSuiteTab("Desync Scanner", new CortexTab(api, replayer));
        api.userInterface().registerContextMenuItemsProvider(new DesyncContextMenu(api, replayer));
    }
}