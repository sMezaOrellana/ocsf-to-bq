from pathlib import Path
from functools import lru_cache
import os
import sys
import logging
import argparse
import json
import re

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def list_files_in_directory(directory_path):
    if not os.path.isdir(directory_path):
        logger.error(
            "Provided path '%s' is not a valid directory.", directory_path)
        return

    logger.info("Listing files in directory: %s", directory_path)
    try:
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            if os.path.isfile(filepath):
                yield filepath
    except Exception as e:
        logger.exception("Erro: %s", e)


def list_dirs_in_directory(directory_path):
    if not os.path.isdir(directory_path):
        logger.error(
            "Provided path '%s' is not a valid directory.", directory_path)
        return

    logger.info("Listing files in directory: %s", directory_path)
    try:
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            if os.path.isdir(filepath):
                yield filepath
    except Exception as e:
        logger.exception("Erro: %s", e)


OCSF_TO_BQ_TYPE = {
    "boolean_t": "BOOL",
    "datetime_t": "TIMESTAMP",
    "date_t": "DATE",
    "double_t": "FLOAT64",
    "float_t": "FLOAT64",
    "integer_t": "INT64",
    "long_t": "INT64",
    "short_t": "INT64",
    "string_t": "STRING",
    "keyword_t": "STRING",
    "text_t": "STRING",
    "uuid_t": "STRING",
    "mac_address_t": "STRING",
    "ip_address_t": "STRING",
    "port_t": "INT64",
    "hostname_t": "STRING",
    "uri_t": "STRING",
    "url_t": "STRING",
    "email_address_t": "STRING",
    "username_t": "STRING",
    "path_t": "STRING",
    "json_t": "JSON",
    "ip_t": "STRING",
    "resource_uid_t": "STRING",
    "email_t": "STRING",
    "bytestring_t": "BYTES",
    "file_hash_t": "STRING",
    "timestamp_t": "INT64",
    "file_path_t": "STRING",
    "file_name_t": "STRING",
    "process_name_t": "STRING",
    "mac_t": "STRING",
    "subnet_t": "STRING",
}


def robust_open(path):
    try:
        with open(path, 'r', encoding='utf-8') as file:
            try:
                dictionary = json.load(file)
                return dictionary
                if not isinstance(dictionary, dict):
                    logger.error(
                        f"Error: The file '{path}' does not contain a valid dictionary.")
            except json.JSONDecodeError as e:
                logger.error(f"Error: Failed to decode JSON. {e}")
    except FileNotFoundError:
        logger.error(f"Error: File not found '{path}'")
    except PermissionError:
        logger.error(f"Error: Permission denied to read '{path}'")
    except OSError as e:
        logger.error(
            f"Error: OS error while accessing file '{path}': {e}")


def build_dictionary_to_bq(directory_path):
    dictionary_path = directory_path + "/" + "dictionary.json"
    if not os.path.isfile(dictionary_path):
        logger.error(f"Error: File does not exist at path '{dictionary_path}'")

    ocsf_dictionary = robust_open(dictionary_path)

    ocsf_attributes = ocsf_dictionary["attributes"]

    big_query_types = {}

    big_query_types_structs = {}
    for attribute, value in ocsf_attributes.items():
        v = value["type"]
        is_arr = value.get("is_array", False)
        if v in OCSF_TO_BQ_TYPE.keys():
            if is_arr:
                big_query_types[attribute] = f"ARRAY<{OCSF_TO_BQ_TYPE[v]}>"
            else:
                big_query_types[attribute] = OCSF_TO_BQ_TYPE[v]
        else:
            if is_arr:
                big_query_types_structs[attribute] = f"ARRAY<STRUCT<{{{v}}}>>"
            else:
                big_query_types_structs[attribute] = f"STRUCT<{{{v}}}>"

    objects_path = directory_path + "/" + "objects"
    objects = {}

    for structure, template in big_query_types_structs.items():
        build_ocsf_attributes_recursive(
            objects_path, template,
            big_query_types, big_query_types_structs,
            objects, structure
        )

    return objects, big_query_types


visited = set()


def build_ocsf_attributes_recursive(objects_path, template, big_query_types, big_query_types_structs, objects, structure):
    if structure in {"xattributes", "proxy", "unmapped", "proxy_endpoint"}:
        return ""

    bq_keywords = {"group", "groups", "desc"}
    s = re.findall(r"\{(.*?)\}", template)[0]

    save_struct = structure != s

    if s in visited:
        return f"{s}__id STRING"

    visited.add(s)

    object_path = objects_path + "/" + s + ".json"
    object_dictionary = robust_open(object_path)
    res = []

    for t, value in object_dictionary["attributes"].items():
        if t in big_query_types.keys():
            if t in bq_keywords:
                x = "__" + t
            else:
                x = t
            res.append(f"{x} {big_query_types[t]}")
        elif t in objects.keys():
            res.append(objects[t])
        elif t == "$include":
            # TODO: handle this include case
            continue
        elif t in {"xattributes", "proxy", "unmapped", "proxy_endpoint"}:
            continue
        else:
            r = build_ocsf_attributes_recursive(
                objects_path, big_query_types_structs[t],
                big_query_types, big_query_types_structs,
                objects, t
            )

            if t in bq_keywords:
                x = "__" + t
            else:
                x = t
            res.append(f"{x} STRUCT<{r}>")

    visited.remove(s)

    final = ", ".join(res)
    if "ARRAY<" in template:
        ss = s + "s"
        if ss in bq_keywords:
            ss = "__" + ss

        finals = template.format(**{s: final})
        objects[ss] = ss + " " + finals
        if save_struct:
            objects[structure] = ss + " " + finals

    if s in bq_keywords:
        s = "__" + s
    final_x = f"{s} STRUCT<{final}>"
    objects[s] = final_x

    if save_struct:
        if structure in bq_keywords:
            x = "__" + structure
        else:
            x = structure
        objects[structure] = f"{x} STRUCT<{final}>"

    return final


def parse_ocsf_events(ocsf_objects, ocsf_types, input_dir):
    events_path = input_dir + "/" + "events"

    ocsf_events_bq = {}
    parse_ocsf_event("base_event", events_path + "/" + "base_event.json",
                     ocsf_events_bq, ocsf_objects, ocsf_types)

    for file_path_dir in list_dirs_in_directory(events_path):
        for file_path_event in list_files_in_directory(file_path_dir):
            stem = Path(file_path_event).stem
            parse_ocsf_event(stem, file_path_event,
                             ocsf_events_bq, ocsf_objects, ocsf_types)

    return ocsf_events_bq


def parse_ocsf_event(name, path, ocsf_events_bq, ocsf_objects, ocsf_types):
    ocsf_events = robust_open(path)

    if name not in ocsf_events_bq.keys():
        ocsf_events_bq[name] = {}

    if extend_name := ocsf_events.get("extends"):
        extend = ocsf_events_bq.get(extend_name)
        if not extend:
            parent_path = str(Path(path).parent)
            parse_ocsf_event(
                extend_name, parent_path + "/"+extend_name+".json",
                ocsf_events_bq, ocsf_objects, ocsf_types)
            extend = ocsf_events_bq.get(extend_name)
    else:
        extend = {}

    for t, v in ocsf_events["attributes"].items():
        if t in ocsf_objects.keys():
            ocsf_events_bq[name][t] = ocsf_objects[t]
        elif t in ocsf_types.keys():
            ocsf_events_bq[name][t] = t + " " + ocsf_types[t]
        elif t in {"xattributes", "proxy", "unmapped", "proxy_endpoint"}:
            continue
        elif t in {"$include"}:
            # TODO: handle this include case
            continue

    ocsf_events_bq[name] |= extend


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate BigQuery DDL from OCSF schema.")
    parser.add_argument(
        "--ocsf-input-dir",
        required=True,
        help="Path to the OCSF schema input directory."
    )
    parser.add_argument(
        "--ocsf-output-dir",
        required=True,
        help="Directory to write output SQL files."
    )
    parser.add_argument(
        "events",
        nargs="+",
        help="Names of OCSF events to generate tables for (e.g. process_activity ssh_activity)"
    )
    return parser.parse_args()


def create_big_query_table_string(table_name, dataset_name, ocsf_events_bq):
    table_query_string = """
CREATE OR REPLACE TABLE {dataset_name}.{table_name} (
    {structure}
);
    """
    l = [value for key, value in ocsf_events_bq[table_name].items()]
    structure = ",\n".join(l)
    print(table_query_string.format(dataset_name=dataset_name,
          table_name=table_name, structure=structure))


if __name__ == "__main__":
    args = parse_args()
    input_dir = args.ocsf_input_dir
    output_dir = args.ocsf_output_dir
    events = args.events

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    ocsf_objects, ocsf_types = build_dictionary_to_bq(input_dir)
    ocsf_events_bq = parse_ocsf_events(ocsf_objects, ocsf_types, input_dir)

    for event_name in events:
        if event_name not in ocsf_events_bq:
            logger.warning(
                f"Event '{event_name}' not found in parsed events. Skipping.")
            continue

        table_sql = """
CREATE OR REPLACE TABLE {dataset_name}.{table_name} (
    {structure}
);
        """.strip().format(
            dataset_name="oscf_test",
            table_name=event_name,
            structure=",\n    ".join(ocsf_events_bq[event_name].values())
        )

        output_path = os.path.join(output_dir, f"{event_name}.sql")
        with open(output_path, "w") as f:
            f.write(table_sql)
            logger.info(
                f"Wrote table SQL for '{event_name}' to '{output_path}'")
