package ewave.ui;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.NotFoundResponse;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Serves the optional dashboard through the same HTTP guards as the API. */
final class BundledFrontend {
    private static final String ROOT = "/ewave-dashboard/";
    private static final Set<String> PAGES = Set.of("overview", "discovery", "privacy", "identification",
            "movement", "ops", "session", "sniper", "spotter", "whistleblower", "de-cloaker",
            "inspector", "profiler", "tracker", "lookout", "capture-health", "saved-results", "settings");
    private static final Map<String, String> ASSET_TYPES = Map.of(
            "js", "text/javascript", "css", "text/css", "svg", "image/svg+xml",
            "png", "image/png", "woff2", "font/woff2", "ico", "image/x-icon");
    private static final Pattern ASSET = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9]+");

    private BundledFrontend() { }

    static void register(Javalin app) {
        if (BundledFrontend.class.getResource(ROOT + "index.html") == null) return;
        app.get("/", BundledFrontend::index);
        for (String page : PAGES) app.get("/" + page, BundledFrontend::index);
        for (var category : Map.of(
                "discovery", Set.of("sniper", "spotter"),
                "privacy", Set.of("whistleblower", "de-cloaker"),
                "identification", Set.of("inspector", "profiler"),
                "movement", Set.of("tracker", "lookout"),
                "session", Set.of("capture-health", "saved-results", "settings")).entrySet()) {
            for (String tab : category.getValue()) app.get("/" + category.getKey() + "/" + tab, BundledFrontend::index);
        }
        app.get("/assets/{name}", ctx -> {
            String name = ctx.pathParam("name");
            if (!ASSET.matcher(name).matches()) throw new NotFoundResponse();
            String type = ASSET_TYPES.get(name.substring(name.lastIndexOf('.') + 1));
            if (type == null) throw new NotFoundResponse();
            asset(ctx, "assets/" + name, type);
        });
    }

    private static void index(Context ctx) {
        asset(ctx, "index.html", "text/html; charset=utf-8");
    }

    private static void asset(Context ctx, String path, String contentType) {
        var stream = BundledFrontend.class.getResourceAsStream(ROOT + path);
        if (stream == null) throw new NotFoundResponse();
        ctx.contentType(contentType).result(stream);
    }
}
