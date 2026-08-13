package com.maciejgojny.desync;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.maciejgojny.desync.menu.DesyncContextMenu;
import com.maciejgojny.desync.replay.DesyncReplayer;
import com.maciejgojny.desync.ui.CortexTab;

import java.util.concurrent.atomic.AtomicBoolean;

public class DesyncExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Desync Hypothesis Scanner - Maciej Gojny");

        DesyncReplayer replayer = new DesyncReplayer();
        AtomicBoolean unloaded = new AtomicBoolean(false);

        // Each entry-point owns its own HypothesisGenerator: the generator carries
        // mutable per-scan configuration, so sharing one instance across the tab and
        // the context menu would let concurrent scans race on its fields.
        CortexTab tab = new CortexTab(api, replayer, unloaded);
        DesyncContextMenu menu = new DesyncContextMenu(api, replayer, unloaded);

        api.userInterface().registerSuiteTab("Desync Scanner", tab);
        api.userInterface().registerContextMenuItemsProvider(menu);

        // Clean unloading (BApp Store requirement): stop scheduling new probes and
        // interrupt any in-flight scan threads when the extension is unloaded.
        api.extension().registerUnloadingHandler(() -> {
            unloaded.set(true);
            tab.shutdown();
            menu.shutdown();
        });
    }
}