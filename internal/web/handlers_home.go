package web

// The home page is a cPanel-style launcher: category sections of tool tiles with
// a live search box, plus a condensed server-health strip. Tools are declared
// here as data so adding a feature is one entry (and role/availability gating
// stays in one place).

// homeTool is one tile. Icon is a key resolved by the "tile-icon" template.
type homeTool struct {
	Name, Desc, Href, Icon string
	External               bool
}

// homeCat is a titled group of tiles (mirrors cPanel's category sections).
type homeCat struct {
	Name  string
	Tools []homeTool
}

// homeVM is the home page's view model: the tile catalog + the live health block.
type homeVM struct {
	Categories []homeCat
	Live       dashboardVM
}

// homeCategories is the tool catalog, filtered by role. Every Href points at a
// page that exists (or handles its own empty/unavailable state), so a tile never
// dead-ends.
func homeCategories(isAdmin bool) []homeCat {
	cats := []homeCat{
		{Name: "Domains", Tools: []homeTool{
			{Name: "Domains", Desc: "Sites, SSL, PHP & deploys", Href: "/domains", Icon: "domains"},
			{Name: "Add Domain", Desc: "Point a new domain here", Href: "/domains/new", Icon: "add"},
		}},
		{Name: "Files", Tools: []homeTool{
			{Name: "File Manager", Desc: "Browse, edit & upload files", Href: "/files", Icon: "files"},
		}},
		{Name: "Databases", Tools: []homeTool{
			{Name: "MySQL Databases", Desc: "Databases & users", Href: "/databases", Icon: "database"},
			{Name: "phpMyAdmin", Desc: "Run SQL in the browser", Href: "/phpmyadmin/", Icon: "phpmyadmin", External: true},
		}},
		{Name: "Advanced", Tools: []homeTool{
			{Name: "Cron Jobs", Desc: "Scheduled commands", Href: "/cron", Icon: "cron"},
		}},
	}
	if isAdmin {
		cats = append(cats, homeCat{Name: "Preferences", Tools: []homeTool{
			{Name: "Users", Desc: "Hosting accounts", Href: "/users", Icon: "users"},
			{Name: "Settings", Desc: "Panel & server settings", Href: "/settings", Icon: "settings"},
		}})
	}
	return cats
}
