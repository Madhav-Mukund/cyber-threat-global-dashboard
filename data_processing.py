#!/usr/bin/env python3
"""
Data Processing & Analysis Pipeline for EURepoC Cybersecurity Incidents v1.3.2
Generates: 15 static charts (PNG), dashboard_data.json, data_quality.json
"""

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import json
import os
from pathlib import Path

# ─── Configuration ───────────────────────────────────────────────────────────

DISGUISED_NULLS = ['Not available', 'Unknown', 'Not attributed', '']
CHART_DIR = Path('charts')
DASHBOARD_DIR = Path('dashboard')
CHART_DIR.mkdir(exist_ok=True)
DASHBOARD_DIR.mkdir(exist_ok=True)

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 11,
    'axes.spines.top': False,
    'axes.spines.right': False,
    'axes.facecolor': '#fafafa',
    'figure.facecolor': 'white',
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--',
})

TEAL    = '#0d9488'
EMERALD = '#059669'
DGREEN  = '#1a5c3a'
RED     = '#dc2626'
AMBER   = '#d97706'
BLUE    = '#2563eb'
PURPLE  = '#7c3aed'
SLATE   = '#475569'
PALETTE = ['#0d9488', '#2563eb', '#d97706', '#dc2626', '#7c3aed', '#059669', '#db2777', '#0891b2']


# ─── Data Loading ────────────────────────────────────────────────────────────

def load_data():
    print("Loading datasets...")
    df   = pd.read_csv('eurepoc_global_dataset_1_3.csv',      low_memory=False)
    dyad = pd.read_csv('eurepoc_dyadic_dataset_0_1.csv',      low_memory=False)
    attr = pd.read_csv('eurepoc_attribution_dataset_1.3.csv',  low_memory=False)
    recv = pd.read_csv('eurepoc_receiver_dataset_1.3.csv',     low_memory=False)

    df['start_date'] = pd.to_datetime(df['start_date'], errors='coerce', dayfirst=True)
    df['end_date']   = pd.to_datetime(df['end_date'],   errors='coerce', dayfirst=True)
    df['year']       = df['start_date'].dt.year

    dyad['start_date'] = pd.to_datetime(dyad['start_date'], errors='coerce', dayfirst=True)
    dyad['year']       = dyad['start_date'].dt.year

    print(f"  Global:      {df.shape}")
    print(f"  Dyadic:      {dyad.shape}")
    print(f"  Attribution: {attr.shape}")
    print(f"  Receiver:    {recv.shape}")
    return df, dyad, attr, recv


# ─── Data Quality ────────────────────────────────────────────────────────────

def analyze_quality(df, dyad, attr, recv):
    print("\nRunning data quality checks...")
    q = {}

    q['shapes'] = {
        'global': list(df.shape), 'dyadic': list(dyad.shape),
        'attribution': list(attr.shape), 'receiver': list(recv.shape),
    }

    q['duplicates'] = {
        'global_id_dupes':  int(df['incident_id'].duplicated().sum()),
        'global_row_dupes': int(df.duplicated().sum()),
        'dyadic_id_dupes':  int(dyad['dyad_id'].duplicated().sum()),
    }

    same_country  = (df['initiator_country'].fillna('NA') == df['initiator_country.1'].fillna('NA')).all()
    same_category = (df['initiator_category'].fillna('NA') == df['initiator_category.1'].fillna('NA')).all()
    q['redundant_columns'] = {
        'initiator_country_identical':  bool(same_country),
        'initiator_category_identical': bool(same_category),
    }

    cols_to_check = [
        'incident_type','receiver_category','receiver_country','initiator_category',
        'initiator_country','attribution_type','attribution_basis','state_responsibility_actor',
        'cyber_conflict_issue','offline_conflict_issue','zero_days','mitre_initial_access',
        'mitre_impact','user_interaction','economic_impact','il_breach_indicator',
        'evidence_for_sanctions_indicator','response_indicator','casualties',
    ]
    miss_rows = []
    for c in cols_to_check:
        true_na = df[c].isna().mean() * 100
        tok = df[c].astype(str).str.split(';').str[0]
        disg = tok.isin(['Not available','Unknown','Not attributed']).mean() * 100
        eff = disg if true_na == 0 else min(100, true_na + disg)
        miss_rows.append({'column': c, 'true_nan_pct': round(true_na,1),
                          'disguised_null_pct': round(disg,1),
                          'effective_missing_pct': round(eff,1)})
    q['missingness'] = sorted(miss_rows, key=lambda x: -x['effective_missing_pct'])

    q['dates'] = {
        'start_date_unparseable': int(df['start_date'].isna().sum()),
        'end_date_unparseable':   int(df['end_date'].isna().sum()),
        'end_date_missing_pct':   round(df['end_date'].isna().mean()*100, 1),
        'end_before_start': int(((df['end_date'].notna()) & (df['start_date'].notna()) &
                                  (df['end_date'] < df['start_date'])).sum()),
    }

    def dup_rate(col):
        s = df[col].dropna().astype(str)
        return round(s.apply(lambda v: len(v.split(';')) != len(set(p.strip() for p in v.split(';')))).mean()*100, 1)
    q['token_duplication'] = {c: dup_rate(c) for c in
        ['receiver_country','initiator_country','receiver_category','initiator_category','incident_type','receiver_regions']}

    q['date_range'] = {
        'earliest': str(df['start_date'].min().date()),
        'latest':   str(df['start_date'].max().date()),
    }

    print("  Quality checks complete.")
    return q


# ─── Cleaning ────────────────────────────────────────────────────────────────

def clean_data(df):
    print("\nCleaning data...")
    def dedup_tokens(cell):
        if pd.isna(cell): return cell
        parts = [p.strip() for p in str(cell).split(';')]
        seen = []
        for p in parts:
            if p not in seen: seen.append(p)
        return ';'.join(seen)

    drop = [c for c in ['initiator_country.1','initiator_category.1','casualties'] if c in df.columns]
    dc = df.drop(columns=drop)

    for col in ['receiver_country','initiator_country','receiver_category','initiator_category','incident_type','receiver_regions']:
        if col in dc.columns:
            dc[col] = dc[col].apply(dedup_tokens)

    dc['initiator_cat_clean']  = dc['initiator_category'].astype(str).str.split(';').str[0].str.strip()
    dc['issue_clean']          = dc['cyber_conflict_issue'].astype(str).str.split(';').str[0].str.strip()
    dc['not_attributed']       = dc['initiator_cat_clean'].isin(['Not attributed','Unknown','nan'])
    dc['receiver_cat_clean']   = dc['receiver_category'].astype(str).str.split(';').str[0].str.strip()
    dc['incident_type_clean']  = dc['incident_type'].astype(str).str.split(';').str[0].str.strip()
    dc['duration_days']        = (dc['end_date'] - dc['start_date']).dt.days

    print(f"  Cleaned shape: {dc.shape}")
    return dc


# ─── Charts ──────────────────────────────────────────────────────────────────

def _save(fig, name):
    fig.savefig(CHART_DIR / name, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  ✓ {name}")

def generate_charts(dc, dyad, quality):
    print("\nGenerating charts...")

    # 1 — Missingness
    fig, ax = plt.subplots(figsize=(10,8))
    ms = sorted(quality['missingness'], key=lambda x: x['effective_missing_pct'])
    cols_m, vals_m = [m['column'] for m in ms], [m['effective_missing_pct'] for m in ms]
    colors = [RED if v>=60 else AMBER if v>=25 else EMERALD for v in vals_m]
    bars = ax.barh(cols_m, vals_m, color=colors, edgecolor='white', linewidth=.5)
    ax.set_xlabel('Effective Missing Rate (%)', fontweight='bold')
    ax.set_title('Data Quality: Effective Missingness by Field', fontsize=14, fontweight='bold', pad=15)
    ax.axvline(25, color='gray', ls='--', lw=.8, alpha=.5); ax.axvline(60, color='gray', ls='--', lw=.8, alpha=.5)
    for b,v in zip(bars,vals_m): ax.text(b.get_width()+1, b.get_y()+b.get_height()/2, f'{v}%', va='center', fontsize=8)
    plt.tight_layout(); _save(fig, '01_missingness.png')

    # 2 — Incidents by Year
    fig, ax = plt.subplots(figsize=(10,5))
    yr = dc[(dc['year']>=2010)&(dc['year']<=2024)]['year'].value_counts().sort_index()
    bars = ax.bar(yr.index.astype(int), yr.values, color=TEAL, edgecolor='white', lw=.5, zorder=3)
    ax.axvspan(2021.5,2024.5,color=EMERALD,alpha=.07,zorder=1)
    ax.annotate('Russia-Ukraine\nwar era + expanded\ntracking', xy=(2023,yr.max()),
                xytext=(2019.5,yr.max()*.85), arrowprops=dict(arrowstyle='->',color=DGREEN,lw=1.5),
                fontsize=9, color=DGREEN, ha='center')
    ax.set_title('Cyber Incidents by Year (2010–2024)', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Year', fontweight='bold'); ax.set_ylabel('Number of Incidents', fontweight='bold')
    for b in bars:
        if b.get_height()>50: ax.text(b.get_x()+b.get_width()/2, b.get_height()+5, int(b.get_height()), ha='center', fontsize=8)
    plt.tight_layout(); _save(fig, '02_incidents_by_year.png')

    # 3 — Top 10 Initiator Countries
    fig, ax = plt.subplots(figsize=(10,6))
    ti = dc[~dc['initiator_cat_clean'].isin(['Not attributed','Unknown','nan'])]
    ic = ti['initiator_country'].dropna().str.split(';').explode().str.strip()
    ic = ic[~ic.isin(DISGUISED_NULLS)]
    tc = ic.value_counts().head(10).sort_values()
    bars = ax.barh(tc.index, tc.values, color=TEAL, edgecolor='white', lw=.5)
    ax.set_title('Top 10 Attributed Initiator Countries', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Incidents', fontweight='bold')
    for b in bars: ax.text(b.get_width()+2, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '03_top_initiator_countries.png')

    # 4 — Initiator Category
    fig, ax = plt.subplots(figsize=(9,5.5))
    cats = dc['initiator_cat_clean'].value_counts().head(8).sort_values()
    clrs = [TEAL if c not in ['Not attributed','Unknown','nan'] else SLATE for c in cats.index]
    bars = ax.barh(cats.index, cats.values, color=clrs, edgecolor='white', lw=.5)
    ax.set_title('Initiator Category (Who Launched the Attack)', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Incidents', fontweight='bold')
    for b in bars: ax.text(b.get_width()+2, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '04_initiator_category.png')

    # 5 — Receiver Category
    fig, ax = plt.subplots(figsize=(10,6))
    rc = dc['receiver_cat_clean'].value_counts()
    rc = rc[~rc.index.isin(DISGUISED_NULLS+['nan'])].head(10).sort_values()
    bars = ax.barh(rc.index, rc.values, color=BLUE, edgecolor='white', lw=.5)
    ax.set_title('Top Target Sectors (Receiver Category)', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Incidents', fontweight='bold')
    for b in bars: ax.text(b.get_width()+2, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '05_receiver_category.png')

    # 6 — Top Attack Corridors
    fig, ax = plt.subplots(figsize=(10,7))
    mask = (~dyad['initiator_country'].isin(DISGUISED_NULLS)) & (~dyad['receiver_country'].isin(DISGUISED_NULLS)) \
           & dyad['initiator_country'].notna() & dyad['receiver_country'].notna()
    pairs = dyad[mask].groupby(['initiator_country','receiver_country']).size().sort_values(ascending=False).head(12)
    labels = [f"{a} → {b}" for a,b in pairs.index]
    bars = ax.barh(labels[::-1], pairs.values[::-1], color=TEAL, edgecolor='white', lw=.5)
    ax.set_title('Top 12 Attributed Attack Corridors', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Dyadic Records', fontweight='bold')
    for b in bars: ax.text(b.get_width()+1, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '06_attack_corridors.png')

    # 7 — Intensity Boxplot
    fig, ax = plt.subplots(figsize=(9,5.5))
    box_cats = ['State','State affiliated actor','Non-state-group','Individual hacker(s)']
    data_box = [dc.loc[dc['initiator_cat_clean']==c,'weighted_intensity'].dropna().values for c in box_cats]
    bp = ax.boxplot(data_box, tick_labels=[c.replace(' ','\n') for c in box_cats], showfliers=False,
                    patch_artist=True, boxprops=dict(facecolor=TEAL,alpha=.6), medianprops=dict(color=RED,lw=2))
    ax.set_title('Weighted Incident Intensity by Initiator Category', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel('Weighted Intensity Score', fontweight='bold')
    plt.tight_layout(); _save(fig, '07_intensity_boxplot.png')

    # 8 — MITRE ATT&CK
    fig, ax = plt.subplots(figsize=(10,6))
    mi = dc['mitre_initial_access'].value_counts()
    mi = mi[~mi.index.isin(DISGUISED_NULLS+['nan'])].head(8).sort_values()
    pop = len(dc[~dc['mitre_initial_access'].isin(DISGUISED_NULLS+['nan']) & dc['mitre_initial_access'].notna()])
    pct = round(pop/len(dc)*100,1)
    bars = ax.barh(mi.index, mi.values, color=PURPLE, edgecolor='white', lw=.5)
    ax.set_title(f'Top MITRE ATT&CK Initial Access Techniques\n({pct}% of incidents have this field populated)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Incidents', fontweight='bold')
    for b in bars: ax.text(b.get_width()+1, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '08_mitre_initial_access.png')

    # 9 — Attribution Difficulty
    fig, ax = plt.subplots(figsize=(10,5))
    ya = dc[(dc['year']>=2011)&(dc['year']<=2024)].groupby('year')['not_attributed'].mean()*100
    ax.plot(ya.index, ya.values, marker='o', color=RED, lw=2, ms=6, zorder=3)
    ax.fill_between(ya.index, ya.values, alpha=.1, color=RED)
    ax.axvspan(2023.5,2024.5, color='yellow', alpha=.1, zorder=1)
    ax.annotate('Recency bias:\nrecent incidents\nnot yet attributed', xy=(2024,ya.iloc[-1]),
                xytext=(2020.5,75), arrowprops=dict(arrowstyle='->',color='gray'), fontsize=8, color='gray', ha='center')
    ax.set_title('Share of Incidents with No Confident Attribution, by Year', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel('% Not Attributed / Unknown', fontweight='bold'); ax.set_xlabel('Year', fontweight='bold')
    ax.set_ylim(0,100)
    plt.tight_layout(); _save(fig, '09_attribution_difficulty.png')

    # 10 — Zero-Day Trend
    fig, ax = plt.subplots(figsize=(10,5))
    zd = dc[dc['zero_days'].isin(['Yes','No'])].copy()
    zdy = zd[(zd['year']>=2011)&(zd['year']<=2024)].groupby('year')['zero_days'].apply(lambda s: (s=='Yes').mean()*100)
    ax.plot(zdy.index, zdy.values, marker='o', color=EMERALD, lw=2, ms=6, zorder=3)
    ax.fill_between(zdy.index, zdy.values, alpha=.1, color=EMERALD)
    n_zd = int((dc['zero_days']=='Yes').sum())
    ax.set_title(f'Share of Incidents Involving a Zero-Day, by Year\n(n={n_zd} — small sample, interpret with caution)',
                 fontsize=13, fontweight='bold', pad=15)
    ax.set_ylabel('% Involving a Zero-Day', fontweight='bold'); ax.set_xlabel('Year', fontweight='bold')
    plt.tight_layout(); _save(fig, '10_zero_day_trend.png')

    # 11 — Incident Type Trends
    fig, ax = plt.subplots(figsize=(10,5.5))
    tcols = ['Data theft','Disruption','Hijacking with Misuse','Ransomware']
    tcols = [c for c in tcols if c in dyad.columns]
    dy = dyad[(dyad['year']>=2016)&(dyad['year']<=2024)]
    trend = dy.groupby('year')[tcols].sum()
    for i,col in enumerate(tcols):
        ax.plot(trend.index, trend[col], marker='o', label=col, color=PALETTE[i], lw=2, ms=5)
    ax.set_title('Incident Type Volume Over Time (2016–2024)', fontsize=14, fontweight='bold', pad=15)
    ax.set_ylabel('Number of Dyadic Records', fontweight='bold'); ax.set_xlabel('Year', fontweight='bold')
    ax.legend(fontsize=9, frameon=True, fancybox=True, shadow=True)
    plt.tight_layout(); _save(fig, '11_incident_type_trends.png')

    # 12 — Conflict Issue × Initiator Heatmap
    fig, ax = plt.subplots(figsize=(10,5.5))
    tiss = dc['issue_clean'].value_counts()
    tiss = tiss[~tiss.index.isin(DISGUISED_NULLS+['nan'])].head(6).index.tolist()
    tc2 = ['State','State affiliated actor','Non-state-group','Individual hacker(s)']
    heat = np.zeros((len(tc2),len(tiss)))
    for i,c in enumerate(tc2):
        for j,iss in enumerate(tiss):
            heat[i,j] = ((dc['initiator_cat_clean']==c)&(dc['issue_clean']==iss)).sum()
    im = ax.imshow(heat, cmap='YlGnBu', aspect='auto')
    ax.set_xticks(range(len(tiss))); ax.set_xticklabels(tiss, rotation=30, ha='right', fontsize=9)
    ax.set_yticks(range(len(tc2))); ax.set_yticklabels(tc2, fontsize=9)
    for i in range(len(tc2)):
        for j in range(len(tiss)):
            ax.text(j,i,int(heat[i,j]),ha='center',va='center',fontsize=9,fontweight='bold')
    ax.set_title('Cyber Conflict Issue by Initiator Category', fontsize=14, fontweight='bold', pad=15)
    plt.colorbar(im, label='Incident Count', shrink=.8)
    plt.tight_layout(); _save(fig, '12_issue_initiator_heatmap.png')

    # 13 — Incident Type × Receiver Heatmap
    fig, ax = plt.subplots(figsize=(12,7))
    ti2 = dc['receiver_cat_clean'].value_counts()
    ti2 = ti2[~ti2.index.isin(DISGUISED_NULLS+['nan'])].head(8).index.tolist()
    acats = dc['incident_type'].str.split(';').explode().str.strip().value_counts()
    acats = acats[~acats.index.isin(DISGUISED_NULLS+['nan'])].head(7).index.tolist()
    heat2 = np.zeros((len(ti2),len(acats)))
    for i,r in enumerate(ti2):
        mask_r = dc['receiver_cat_clean']==r
        types_r = dc.loc[mask_r,'incident_type'].str.split(';').explode().str.strip()
        cts = types_r.value_counts()
        for j,cat in enumerate(acats):
            heat2[i,j] = cts.get(cat,0)
    im = ax.imshow(heat2, cmap='YlOrRd', aspect='auto')
    acats_short = [c[:18]+'…' if len(c)>20 else c for c in acats]
    ti2_short = [r[:18]+'…' if len(r)>20 else r for r in ti2]
    ax.set_xticks(range(len(acats))); ax.set_xticklabels(acats_short, rotation=30, ha='right', fontsize=9)
    ax.set_yticks(range(len(ti2))); ax.set_yticklabels(ti2_short, fontsize=9)
    for i in range(len(ti2)):
        for j in range(len(acats)):
            ax.text(j,i,int(heat2[i,j]),ha='center',va='center',fontsize=8,fontweight='bold')
    ax.set_title('Incident Type by Receiver Category', fontsize=14, fontweight='bold', pad=15)
    plt.colorbar(im, label='Incident Count', shrink=.8)
    plt.tight_layout(); _save(fig, '13_type_receiver_heatmap.png')

    # 14 — Duration Distribution
    fig, ax = plt.subplots(figsize=(10,5))
    dur = dc['duration_days'].dropna()
    dur = dur[(dur>=0)&(dur<=365)]
    ax.hist(dur, bins=50, color=TEAL, edgecolor='white', lw=.5, alpha=.8)
    med = dur.median()
    ax.axvline(med, color=RED, ls='--', lw=2, label=f'Median: {med:.0f} days')
    ax.set_title('Incident Duration Distribution (capped at 365 days)', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Duration (days)', fontweight='bold'); ax.set_ylabel('Number of Incidents', fontweight='bold')
    ax.legend(fontsize=10)
    plt.tight_layout(); _save(fig, '14_duration_distribution.png')

    # 15 — Top Receiver Countries
    fig, ax = plt.subplots(figsize=(10,6))
    rcc = dc['receiver_country'].dropna().str.split(';').explode().str.strip()
    rcc = rcc[~rcc.isin(DISGUISED_NULLS+['nan'])]
    trv = rcc.value_counts().head(15).sort_values()
    bars = ax.barh(trv.index, trv.values, color=BLUE, edgecolor='white', lw=.5)
    ax.set_title('Top 15 Most Targeted Countries', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Number of Incidents', fontweight='bold')
    for b in bars: ax.text(b.get_width()+2, b.get_y()+b.get_height()/2, int(b.get_width()), va='center', fontsize=9)
    plt.tight_layout(); _save(fig, '15_top_receiver_countries.png')

    print("  All 15 charts generated!")


# ─── Dashboard Data Export ───────────────────────────────────────────────────

def export_dashboard_data(dc, dyad):
    print("\nExporting dashboard data...")
    d = {}

    # --- Geocoding Mapping for 3D Globe ---
    try:
        centroids_df = pd.read_csv('countries_centroids.csv')
        centroid_dict = {row['COUNTRY'].lower(): (float(row['latitude']), float(row['longitude'])) for _, row in centroids_df.iterrows()}
    except Exception as e:
        print(f"Warning: Failed to load countries_centroids.csv: {e}")
        centroid_dict = {}

    # Unique country list from Eurepoc
    init_countries = set(dc['initiator_country'].dropna().str.split(';').explode().str.strip())
    recv_countries = set(dc['receiver_country'].dropna().str.split(';').explode().str.strip())
    dyad_init = set(dyad['initiator_country'].dropna().str.split(';').explode().str.strip())
    dyad_recv = set(dyad['receiver_country'].dropna().str.split(';').explode().str.strip())
    all_countries = init_countries | recv_countries | dyad_init | dyad_recv

    coords_map = {}
    custom_coords = {
        'asia (region)': (34.0479, 100.6197),
        'balkans (region)': (44.7866, 20.4489),
        'caucasus': (41.7151, 44.8271),
        'central america (region)': (12.7690, -85.6024),
        'central asia (region)': (51.1694, 71.4491),
        'eu (institutions)': (50.8503, 4.3517),
        'eu (region)': (50.8503, 4.3517),
        'eastern asia (region)': (36.0000, 127.0000),
        'eastern europe': (52.2297, 21.0122),
        'eastern europe, russia': (55.7558, 37.6173),
        'europe (region)': (48.8566, 2.3522),
        'europe (region), south america': (48.8566, 2.3522),
        'global (region)': (0.0, 0.0),
        'guild countries (region)': (25.2769, 51.5200),
        'gulf countries (region)': (25.2769, 51.5200),
        'hong kong': (22.3193, 114.1694),
        'isis': (35.1318, 37.9838),
        'international association of athletics federations': (43.7384, 7.4246),
        'interpol': (45.7640, 4.8357),
        'kosovo': (42.6026, 20.9030),
        'macao': (22.1987, 113.5439),
        'mena region (region)': (26.8206, 30.8025),
        'middle east (region)': (24.7136, 46.6753),
        'nato (institutions)': (50.8503, 4.3517),
        'nato (region)': (50.8503, 4.3517),
        'north africa (region)': (26.8206, 30.8025),
        'north america': (48.3689, -99.9962),
        'northeast asia (region)': (40.0000, 115.0000),
        'northern europe': (60.1282, 18.6435),
        'oceania (region)': (-25.2744, 133.7751),
        'organization for security and cooperation in europe': (48.2082, 16.3738),
        'palestine': (31.9522, 35.2332),
        'south america': (-8.7832, -55.4915),
        'south asia (region)': (22.3511, 78.6677),
        'southeast asia (region)': (1.3521, 103.8198),
        'southeast asia (region), not available': (1.3521, 103.8198),
        'st. vincent and the grenadines': (12.9843, -61.2872),
        'swaziland': (-26.5225, 31.4659),
        'taiwan': (23.6978, 120.9605),
        'unicef': (46.2044, 6.1432),
        'united nations': (46.2044, 6.1432),
        'united nations economic and social council': (40.7128, -74.0060),
        'united nations environment programme': (-1.2921, 36.8219),
        'united nations organization': (40.7128, -74.0060),
        'virgin islands, british': (18.4207, -64.6400),
        'western europe': (48.8566, 2.3522),
        'world anti-doping agency': (45.5017, -73.5673),
    }

    aliases = {
        'united states': 'united states',
        'vietnam': 'viet nam',
        'russia': 'russian federation',
        'south korea': 'korea, republic of',
        'north korea': "korea, democratic people's republic of",
        'iran': 'iran, islamic republic of',
        'syria': 'syrian arab republic',
        'venezuela': 'venezuela, bolivarian republic of',
        'bolivia': 'bolivia, plurinational state of',
        'taiwan': 'taiwan, province of china',
        'tanzania': 'tanzania, united republic of',
        'united kingdom': 'united kingdom',
        'palestine': 'palestine, state of',
        'moldova': 'moldova, republic of',
        'brunei': 'brunei darussalam',
        'laos': "lao people's democratic republic",
        'micronesia': 'micronesia, federated states of',
        'cape verde': 'cabo verde',
        'ivory coast': "côte d'ivoire",
        'macau': 'macao',
        'holy see': 'holy see (vatican city state)',
        'vatican city': 'holy see (vatican city state)',
    }

    for c in all_countries:
        c_clean = c.strip()
        if not c_clean or c_clean.lower() in DISGUISED_NULLS or c_clean.lower() in ['nan', 'unknown']:
            continue
        
        cl = c_clean.lower()
        if cl in custom_coords:
            coords_map[c_clean] = custom_coords[cl]
        elif cl in centroid_dict:
            coords_map[c_clean] = centroid_dict[cl]
        elif cl in aliases and aliases[cl] in centroid_dict:
            coords_map[c_clean] = centroid_dict[aliases[cl]]
        else:
            # Substring match
            found = False
            for name, coords in centroid_dict.items():
                if cl in name or name in cl:
                    coords_map[c_clean] = coords
                    found = True
                    break
            if not found:
                coords_map[c_clean] = (0.0, 0.0)

    d['country_coords'] = coords_map

    # --- Summary KPIs ---
    total = len(dc)
    attributed = int((~dc['not_attributed']).sum())
    attr_rate = round(attributed/total*100, 1)
    ic = dc[~dc['not_attributed']]['initiator_country'].dropna().str.split(';').explode().str.strip()
    ic = ic[~ic.isin(DISGUISED_NULLS+['nan'])]
    top_att = ic.value_counts().index[0] if len(ic)>0 else 'Unknown'
    rcc = dc['receiver_country'].dropna().str.split(';').explode().str.strip()
    rcc = rcc[~rcc.isin(DISGUISED_NULLS+['nan'])]
    d['summary'] = {
        'total_incidents': int(total), 'attributed_incidents': attributed,
        'attribution_rate': attr_rate, 'top_attacker': top_att,
        'countries_affected': int(rcc.nunique()),
        'date_range_start': str(dc['start_date'].min().date()),
        'date_range_end': str(dc['start_date'].max().date()),
        'year_min': int(dc['year'].dropna().min()), 'year_max': int(dc['year'].dropna().max()),
        'zero_day_incidents': int((dc['zero_days']=='Yes').sum()),
        'state_incidents': int((dc['initiator_cat_clean']=='State').sum()),
    }

    # --- Incidents by Year ---
    yr = dc[(dc['year']>=2000)&(dc['year']<=2024)]['year'].value_counts().sort_index()
    d['incidents_by_year'] = {str(int(k)):int(v) for k,v in yr.items()}

    # --- Top Initiator Countries ---
    d['top_initiator_countries'] = {k:int(v) for k,v in ic.value_counts().head(15).items()}

    # --- Initiator Categories ---
    cats = dc['initiator_cat_clean'].value_counts()
    cats = cats[~cats.index.isin(['nan'])]
    d['initiator_categories'] = {k:int(v) for k,v in cats.items()}

    # --- Receiver Categories ---
    rcats = dc['receiver_cat_clean'].value_counts()
    rcats = rcats[~rcats.index.isin(DISGUISED_NULLS+['nan'])]
    d['receiver_categories'] = {k:int(v) for k,v in rcats.head(12).items()}

    # --- Attack Corridors ---
    mask = (~dyad['initiator_country'].isin(DISGUISED_NULLS)) & (~dyad['receiver_country'].isin(DISGUISED_NULLS)) \
           & dyad['initiator_country'].notna() & dyad['receiver_country'].notna()
    pairs = dyad[mask].groupby(['initiator_country','receiver_country']).size().sort_values(ascending=False).head(15)
    d['attack_corridors'] = [{'from':a,'to':b,'count':int(c)} for (a,b),c in pairs.items()]

    # --- Incident Type Trends ---
    tcols = ['Data theft','Data theft & Doxing','Disruption','Hijacking with Misuse','Hijacking without Misuse','Ransomware']
    tcols = [c for c in tcols if c in dyad.columns]
    dy = dyad[(dyad['year']>=2010)&(dyad['year']<=2024)]
    trend = dy.groupby('year')[tcols].sum()
    d['incident_type_trends'] = {}
    for yr_idx in trend.index:
        d['incident_type_trends'][str(int(yr_idx))] = {col:int(trend.loc[yr_idx,col]) for col in tcols}

    # --- Intensity by Category ---
    int_data = {}
    for c in ['State','State affiliated actor','Non-state-group','Individual hacker(s)','Not attributed']:
        vals = dc.loc[dc['initiator_cat_clean']==c,'weighted_intensity'].dropna()
        if len(vals)>0:
            int_data[c] = {'median':round(float(vals.median()),2),'q1':round(float(vals.quantile(.25)),2),
                           'q3':round(float(vals.quantile(.75)),2),'min':round(float(vals.min()),2),
                           'max':round(float(vals.max()),2),'mean':round(float(vals.mean()),2),'count':int(len(vals))}
    d['intensity_by_category'] = int_data

    # --- MITRE Techniques ---
    mi = dc['mitre_initial_access'].value_counts()
    mi = mi[~mi.index.isin(DISGUISED_NULLS+['nan'])]
    d['mitre_techniques'] = {k:int(v) for k,v in mi.head(10).items()}

    # --- Attribution Over Time ---
    ya = dc[(dc['year']>=2011)&(dc['year']<=2024)].groupby('year')['not_attributed'].mean()*100
    d['attribution_over_time'] = {str(int(k)):round(float(v),1) for k,v in ya.items()}

    # --- Zero-Day Trend ---
    zd = dc[dc['zero_days'].isin(['Yes','No'])].copy()
    zdy = zd[(zd['year']>=2011)&(zd['year']<=2024)].groupby('year')['zero_days'].apply(lambda s:(s=='Yes').mean()*100)
    d['zero_day_trend'] = {str(int(k)):round(float(v),1) for k,v in zdy.items()}

    # --- Top Receiver Countries ---
    d['top_receiver_countries'] = {k:int(v) for k,v in rcc.value_counts().head(15).items()}

    # --- Heatmap: Conflict Issue × Initiator ---
    tiss = dc['issue_clean'].value_counts()
    tiss = tiss[~tiss.index.isin(DISGUISED_NULLS+['nan'])].head(6).index.tolist()
    tc2 = ['State','State affiliated actor','Non-state-group','Individual hacker(s)']
    hm = {}
    for c in tc2:
        hm[c] = {}
        for iss in tiss:
            hm[c][iss] = int(((dc['initiator_cat_clean']==c)&(dc['issue_clean']==iss)).sum())
    d['conflict_issue_heatmap'] = hm
    d['conflict_issues'] = tiss
    d['heatmap_categories'] = tc2

    # --- Heatmap: Receiver × Incident Type ---
    ri = dc['receiver_cat_clean'].value_counts()
    ri = ri[~ri.index.isin(DISGUISED_NULLS+['nan'])].head(8).index.tolist()
    ac = dc['incident_type'].str.split(';').explode().str.strip().value_counts()
    ac = ac[~ac.index.isin(DISGUISED_NULLS+['nan'])].head(7).index.tolist()
    rh = {}
    for r in ri:
        rh[r] = {}
        mr = dc['receiver_cat_clean']==r
        tr = dc.loc[mr,'incident_type'].str.split(';').explode().str.strip()
        cts = tr.value_counts()
        for cat in ac: rh[r][cat] = int(cts.get(cat,0))
    d['receiver_type_heatmap'] = rh
    d['receiver_heatmap_rows'] = ri
    d['receiver_heatmap_cols'] = ac

    # --- Incident Table (expanded for dynamic filtering) ---
    tcols_tbl = ['incident_id','name','year','incident_type','incident_type_clean',
                 'initiator_country','initiator_cat_clean','receiver_country','receiver_cat_clean',
                 'weighted_intensity','mitre_initial_access','issue_clean','zero_days','not_attributed']
    tdf = dc[tcols_tbl].copy()
    tdf = tdf.where(tdf.notna(), '')
    tdf['year'] = tdf['year'].apply(lambda x: int(x) if x!='' and not (isinstance(x,float) and np.isnan(x)) else '')
    tdf['weighted_intensity'] = tdf['weighted_intensity'].apply(
        lambda x: round(float(x),1) if x!='' and not (isinstance(x,float) and np.isnan(x)) else '')
    tdf['not_attributed'] = tdf['not_attributed'].apply(lambda x: bool(x) if x!='' else True)
    d['incidents'] = tdf.to_dict(orient='records')

    out = DASHBOARD_DIR / 'dashboard_data.json'
    with open(out,'w') as f: json.dump(d, f)
    mb = os.path.getsize(out)/(1024*1024)
    print(f"  Dashboard data exported: {out} ({mb:.1f} MB)")

    out_js = DASHBOARD_DIR / 'data.js'
    with open(out_js,'w') as f:
        f.write('// Auto-generated JSONP fallback for file:// protocol\n')
        f.write('window.DASHBOARD_DATA = ')
        f.write(json.dumps(d))
        f.write(';\n')
    mb_js = os.path.getsize(out_js)/(1024*1024)
    print(f"  Dashboard data.js fallback exported: {out_js} ({mb_js:.1f} MB)")
    return d


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    df, dyad, attr, recv = load_data()
    quality = analyze_quality(df, dyad, attr, recv)
    dc = clean_data(df)
    generate_charts(dc, dyad, quality)
    dashboard = export_dashboard_data(dc, dyad)
    with open('data_quality.json','w') as f: json.dump(quality, f, indent=2)
    print("\n✅ All processing complete!")
    print(f"   Charts:         {CHART_DIR}/")
    print(f"   Dashboard data: {DASHBOARD_DIR}/dashboard_data.json")
    print(f"   Quality data:   data_quality.json")
    return quality, dashboard

if __name__ == '__main__':
    main()
