package com.maciejgojny.desync.menu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.maciejgojny.desync.Hypothesis;
import com.maciejgojny.desync.gen.HypothesisGenerator;
import com.maciejgojny.desync.replay.ClassifyResult;
import com.maciejgojny.desync.replay.DesyncReplayer;

import javax.swing.*;
import java.awt.Component;
import java.util.List;
import java.util.Optional;

public class DesyncContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final HypothesisGenerator generator = new HypothesisGenerator();
    private final DesyncReplayer replayer;

    public DesyncContextMenu(MontoyaApi api, DesyncReplayer replayer) {
        this.api = api;
        this.replayer = replayer;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<HttpRequest> maybeRequest = event.messageEditorRequestResponse()
                .map(mer -> mer.requestResponse().request());

        if (maybeRequest.isEmpty()) {
            List<HttpRequest> selected = event.selectedRequestResponses().stream()
                    .map(rr -> rr.request())
                    .toList();
            if (!selected.isEmpty()) {
                maybeRequest = Optional.of(selected.get(0));
            }
        }

        if (maybeRequest.isEmpty()) {
            return List.of();
        }

        HttpRequest request = maybeRequest.get();

        JMenuItem item = new JMenuItem("Run desync hypotheses (quick)");
        item.addActionListener(l -> runQuickScan(request));
        return List.of(item);
    }

    private void runQuickScan(HttpRequest request) {
        String host = request.httpService().host();
        int port = request.httpService().port();
        boolean tls = request.httpService().secure();
        String path = request.path();

        generator.setBase(path == null || path.isEmpty() ? "/" : path);
        List<Hypothesis> hyps = generator.generate(20);

        new Thread(() -> {
            for (Hypothesis hyp : hyps) {
                if ("h2".equals(hyp.nativeEngine)) {
                    api.logging().logToOutput(hyp.id + " -> skipped (h2-native: needs binary HTTP/2 frame engine)");
                    continue;
                }
                ClassifyResult result = replayer.replay(hyp, host, port, tls);
                api.logging().logToOutput(hyp.id + " -> " + result);
            }
            api.logging().logToOutput("Quick desync scan finished for " + host + ":" + port);
        }, "desync-quick-scan").start();
    }
}